// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Screen / VRAM dump for reverse engineering multi-mode DOS games.

#include "screen_dump.h"
#include "game_trace.h"

#include "gui/mapper.h"
#include "hardware/memory.h"
#include "hardware/pic.h"

#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#	include <direct.h>
#	define SCREEN_DUMP_MKDIR(path) _mkdir(path)
#else
#	include <unistd.h>
#	define SCREEN_DUMP_MKDIR(path) mkdir((path), 0755)
#endif

namespace {

struct ModeLayout {
	uint8_t  mode; // BIOS mode (low 7 bits)
	uint32_t base; // physical address
	uint32_t size; // visible page bytes (not full aperture)
	uint16_t cols;
	uint16_t rows;
	const char* kind; // "text" / "cga_gfx" / "ega_vga" / ...
};

// Visible framebuffer contracts for common real-mode BIOS modes.
// full_16k option expands text/CGA dumps from B8000 to 0x4000 separately.
static constexpr ModeLayout k_layouts[] = {
        {0x00, 0xB8000, 0x07D0, 40, 25, "text"},
        {0x01, 0xB8000, 0x07D0, 40, 25, "text"},
        {0x02, 0xB8000, 0x0FA0, 80, 25, "text"},
        {0x03, 0xB8000, 0x0FA0, 80, 25, "text"},
        {0x04, 0xB8000, 0x4000, 320, 200, "cga_gfx"},
        {0x05, 0xB8000, 0x4000, 320, 200, "cga_gfx"},
        {0x06, 0xB8000, 0x4000, 640, 200, "cga_gfx"},
        {0x07, 0xB0000, 0x0FA0, 80, 25, "text_mono"},
        {0x0D, 0xA0000, 0x2000, 320, 200, "ega"},
        {0x0E, 0xA0000, 0x4000, 640, 200, "ega"},
        {0x0F, 0xA0000, 0x7000, 640, 350, "ega"},
        {0x10, 0xA0000, 0x7000, 640, 350, "ega"},
        {0x11, 0xA0000, 0x9600, 640, 480, "vga"},
        {0x12, 0xA0000, 0x9600, 640, 480, "vga"},
        {0x13, 0xA0000, 0xFA00, 320, 200, "vga"},
};

static ScreenDumpConfig s_cfg{};
static bool s_ready = false;

static std::string s_game = "GAME";
static uint8_t s_mode     = 0x03; // DOS starts in text
static uint32_t s_base    = 0xB8000;
static uint32_t s_size    = 0x0FA0;
static uint16_t s_cols    = 80;
static uint16_t s_rows    = 25;
static const char* s_kind = "text";

static uint32_t s_generation = 0; // increments on each mode set
static uint32_t s_seq        = 0; // dump counter

// Delayed dump after mode set
static bool s_delay_pending = false;
static uint32_t s_delay_gen = 0;

static bool ensure_dir(const std::string& path)
{
	if (path.empty() || path == "." || path == "./") {
		return true;
	}
	// Create intermediate components (simple one-level is enough for default)
	if (SCREEN_DUMP_MKDIR(path.c_str()) == 0) {
		return true;
	}
	// EEXIST is fine
	struct stat st{};
	if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
		return true;
	}
	return false;
}

static const ModeLayout* find_layout(const uint8_t mode)
{
	const uint8_t m = mode & 0x7F;
	for (const auto& e : k_layouts) {
		if (e.mode == m) {
			return &e;
		}
	}
	return nullptr;
}

static void apply_mode(const uint8_t mode_byte)
{
	const uint8_t m = mode_byte & 0x7F;
	s_mode          = m;

	if (const auto* lay = find_layout(m)) {
		s_base = lay->base;
		s_size = lay->size;
		s_cols = lay->cols;
		s_rows = lay->rows;
		s_kind = lay->kind;
	} else {
		// Unknown: assume VGA-ish A000 aperture, 64 KiB
		s_base = 0xA0000;
		s_size = 0x10000;
		s_cols = 0;
		s_rows = 0;
		s_kind = "unknown";
	}

	if (s_cfg.full_16k && (s_base == 0xB8000 || s_base == 0xB0000)) {
		s_size = 0x4000;
	}
}

static std::string sanitize_game_name(const char* filename)
{
	if (!filename || !*filename) {
		return "GAME";
	}
	// basename
	const char* base = filename;
	for (const char* p = filename; *p; ++p) {
		if (*p == '/' || *p == '\\' || *p == ':') {
			base = p + 1;
		}
	}
	std::string name(base);
	// strip extension
	const auto dot = name.find_last_of('.');
	if (dot != std::string::npos) {
		name.resize(dot);
	}
	// uppercase alnum / underscore only
	std::string out;
	out.reserve(name.size());
	for (unsigned char c : name) {
		if (std::isalnum(c)) {
			out.push_back(static_cast<char>(std::toupper(c)));
		} else if (c == '-' || c == '_') {
			out.push_back('_');
		}
	}
	if (out.empty()) {
		out = "GAME";
	}
	// cap length for path friendliness
	if (out.size() > 32) {
		out.resize(32);
	}
	return out;
}

static uint32_t dump_size_now()
{
	if (s_cfg.full_16k && (s_base == 0xB8000 || s_base == 0xB0000)) {
		return 0x4000;
	}
	return s_size;
}

static void write_dump_files(const char* reason)
{
	if (!s_ready || !s_cfg.enabled) {
		return;
	}

	const uint32_t size = dump_size_now();
	if (size == 0 || size > 0x100000) {
		return;
	}

	if (!ensure_dir(s_cfg.dir)) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot create screen dump dir '%s'\n",
		        s_cfg.dir.c_str());
		return;
	}

	++s_seq;
	char stem[256];
	snprintf(stem,
	         sizeof(stem),
	         "%s_g%04u_m%02X_b%05X_s%04X_%04u",
	         s_game.c_str(),
	         static_cast<unsigned>(s_generation),
	         static_cast<unsigned>(s_mode),
	         static_cast<unsigned>(s_base),
	         static_cast<unsigned>(size),
	         static_cast<unsigned>(s_seq));

	std::string bin_path = s_cfg.dir;
	if (!bin_path.empty() && bin_path.back() != '/' && bin_path.back() != '\\') {
		bin_path += '/';
	}
	const std::string meta_path = bin_path + stem + ".meta";
	bin_path += stem;
	bin_path += ".bin";

	std::vector<uint8_t> buf(size);
	for (uint32_t i = 0; i < size; ++i) {
		buf[i] = mem_readb(s_base + i);
	}

	FILE* fp = fopen(bin_path.c_str(), "wb");
	if (!fp) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot write screen dump '%s'\n",
		        bin_path.c_str());
		return;
	}
	const size_t nw = fwrite(buf.data(), 1, size, fp);
	fclose(fp);
	if (nw != size) {
		fprintf(stderr,
		        "[debugtrace] WARNING: short write on '%s' (%zu/%u)\n",
		        bin_path.c_str(),
		        nw,
		        static_cast<unsigned>(size));
	}

	if (s_cfg.write_meta) {
		FILE* mf = fopen(meta_path.c_str(), "w");
		if (mf) {
			fprintf(mf, "game=%s\n", s_game.c_str());
			fprintf(mf, "reason=%s\n", reason ? reason : "");
			fprintf(mf, "generation=%u\n", static_cast<unsigned>(s_generation));
			fprintf(mf, "seq=%u\n", static_cast<unsigned>(s_seq));
			fprintf(mf, "mode=0x%02X\n", static_cast<unsigned>(s_mode));
			fprintf(mf, "base=0x%05X\n", static_cast<unsigned>(s_base));
			fprintf(mf, "size=0x%04X\n", static_cast<unsigned>(size));
			fprintf(mf, "cols=%u\n", static_cast<unsigned>(s_cols));
			fprintf(mf, "rows=%u\n", static_cast<unsigned>(s_rows));
			fprintf(mf, "kind=%s\n", s_kind);
			fprintf(mf, "t_ms=%" PRIu64 "\n", DEBUGTRACE_GetElapsedMs());
			fprintf(mf, "layout=char_attr_le\n");
			fclose(mf);
		}
	}

	if (g_trace_enabled || g_debugtrace_system_ready) {
		char line[512];
		snprintf(line,
		         sizeof(line),
		         "[T+%08" PRIu64 "ms] SCREEN DUMP: %s (%u bytes) mode=%02Xh "
		         "base=%05Xh reason=%s",
		         DEBUGTRACE_GetElapsedMs(),
		         bin_path.c_str(),
		         static_cast<unsigned>(size),
		         static_cast<unsigned>(s_mode),
		         static_cast<unsigned>(s_base),
		         reason ? reason : "");
		DEBUGTRACE_Write(line);
	} else {
		fprintf(stderr, "[debugtrace] SCREEN DUMP: %s (%u bytes)\n",
		        bin_path.c_str(),
		        static_cast<unsigned>(size));
	}
}

static void delayed_dump_event(uint32_t /*val*/)
{
	s_delay_pending = false;
	// Only dump if we are still in the same mode generation that requested it
	if (s_delay_gen == s_generation) {
		write_dump_files("mode_set_delayed");
	}
}

static void schedule_or_dump_mode_set()
{
	if (!s_cfg.on_mode_set) {
		return;
	}
	// Only auto-dump once the game is under trace (avoids shell noise)
	if (!g_trace_enabled) {
		return;
	}

	if (s_cfg.on_mode_set_delay_ms <= 0) {
		write_dump_files("mode_set");
		return;
	}

	if (s_delay_pending) {
		PIC_RemoveEvents(delayed_dump_event);
		s_delay_pending = false;
	}
	s_delay_gen     = s_generation;
	s_delay_pending = true;
	PIC_AddEvent(delayed_dump_event,
	             static_cast<double>(s_cfg.on_mode_set_delay_ms));
}

static void hotkey_handler(bool pressed)
{
	if (!pressed) {
		return;
	}
	ScreenDump_Hotkey(true);
}

// Parse "ctrl+alt+f10", "f12", "none", etc. → SDL scancode + MAPPER mod mask.
// Returns false if hotkey is disabled or unparseable.
static bool parse_hotkey(const std::string& spec_in, SDL_Scancode& out_key,
                         uint32_t& out_mods, std::string& out_label)
{
	out_key  = SDL_SCANCODE_UNKNOWN;
	out_mods = 0;
	out_label.clear();

	// Normalize: lowercase, strip spaces
	std::string spec;
	spec.reserve(spec_in.size());
	for (unsigned char c : spec_in) {
		if (c == ' ' || c == '\t') {
			continue;
		}
		spec.push_back(static_cast<char>(std::tolower(c)));
	}

	if (spec.empty() || spec == "none" || spec == "off" || spec == "disabled") {
		return false;
	}

	// Split on +
	std::vector<std::string> parts;
	size_t start = 0;
	while (start <= spec.size()) {
		const size_t plus = spec.find('+', start);
		if (plus == std::string::npos) {
			parts.push_back(spec.substr(start));
			break;
		}
		parts.push_back(spec.substr(start, plus - start));
		start = plus + 1;
	}

	if (parts.empty() || parts.back().empty()) {
		return false;
	}

	// Last token is the key; earlier tokens are modifiers
	const std::string key = parts.back();
	for (size_t i = 0; i + 1 < parts.size(); ++i) {
		const auto& m = parts[i];
		if (m == "ctrl" || m == "control" || m == "primary") {
			out_mods |= PRIMARY_MOD;
		} else if (m == "alt" || m == "opt") {
			out_mods |= MMOD2;
		} else if (m == "shift") {
			// MAPPER has no dedicated shift mod bit for AddHandler defaults;
			// treat as GUI/extra on platforms where MMOD3 is free, else ignore.
			// Use MMOD3 as "GUI" which is rare for dumps; document shift unsupported.
			// Better: document that only ctrl/alt/gui work.
			fprintf(stderr,
			        "[debugtrace] WARNING: 'shift' is not supported in "
			        "screen_dump_hotkey; ignoring\n");
		} else if (m == "gui" || m == "win" || m == "super" || m == "cmd" ||
		           m == "meta") {
			out_mods |= MMOD3;
		} else if (m == "ctrlalt" || m == "ctrl+alt") {
			out_mods |= PRIMARY_MOD | MMOD2;
		} else {
			fprintf(stderr,
			        "[debugtrace] WARNING: unknown modifier '%s' in "
			        "screen_dump_hotkey\n",
			        m.c_str());
			return false;
		}
	}

	// Key name → scancode
	static const struct {
		const char* name;
		SDL_Scancode code;
	} keys[] = {
	        {"f1", SDL_SCANCODE_F1},   {"f2", SDL_SCANCODE_F2},
	        {"f3", SDL_SCANCODE_F3},   {"f4", SDL_SCANCODE_F4},
	        {"f5", SDL_SCANCODE_F5},   {"f6", SDL_SCANCODE_F6},
	        {"f7", SDL_SCANCODE_F7},   {"f8", SDL_SCANCODE_F8},
	        {"f9", SDL_SCANCODE_F9},   {"f10", SDL_SCANCODE_F10},
	        {"f11", SDL_SCANCODE_F11}, {"f12", SDL_SCANCODE_F12},
	        {"a", SDL_SCANCODE_A},     {"b", SDL_SCANCODE_B},
	        {"c", SDL_SCANCODE_C},     {"d", SDL_SCANCODE_D},
	        {"e", SDL_SCANCODE_E},     {"f", SDL_SCANCODE_F},
	        {"g", SDL_SCANCODE_G},     {"h", SDL_SCANCODE_H},
	        {"i", SDL_SCANCODE_I},     {"j", SDL_SCANCODE_J},
	        {"k", SDL_SCANCODE_K},     {"l", SDL_SCANCODE_L},
	        {"m", SDL_SCANCODE_M},     {"n", SDL_SCANCODE_N},
	        {"o", SDL_SCANCODE_O},     {"p", SDL_SCANCODE_P},
	        {"q", SDL_SCANCODE_Q},     {"r", SDL_SCANCODE_R},
	        {"s", SDL_SCANCODE_S},     {"t", SDL_SCANCODE_T},
	        {"u", SDL_SCANCODE_U},     {"v", SDL_SCANCODE_V},
	        {"w", SDL_SCANCODE_W},     {"x", SDL_SCANCODE_X},
	        {"y", SDL_SCANCODE_Y},     {"z", SDL_SCANCODE_Z},
	        {"0", SDL_SCANCODE_0},     {"1", SDL_SCANCODE_1},
	        {"2", SDL_SCANCODE_2},     {"3", SDL_SCANCODE_3},
	        {"4", SDL_SCANCODE_4},     {"5", SDL_SCANCODE_5},
	        {"6", SDL_SCANCODE_6},     {"7", SDL_SCANCODE_7},
	        {"8", SDL_SCANCODE_8},     {"9", SDL_SCANCODE_9},
	        {"insert", SDL_SCANCODE_INSERT},
	        {"delete", SDL_SCANCODE_DELETE},
	        {"home", SDL_SCANCODE_HOME},
	        {"end", SDL_SCANCODE_END},
	        {"pageup", SDL_SCANCODE_PAGEUP},
	        {"pagedown", SDL_SCANCODE_PAGEDOWN},
	        {"printscreen", SDL_SCANCODE_PRINTSCREEN},
	        {"scrolllock", SDL_SCANCODE_SCROLLLOCK},
	        {"pause", SDL_SCANCODE_PAUSE},
	};

	for (const auto& k : keys) {
		if (key == k.name) {
			out_key = k.code;
			break;
		}
	}
	if (out_key == SDL_SCANCODE_UNKNOWN) {
		fprintf(stderr,
		        "[debugtrace] WARNING: unknown key '%s' in screen_dump_hotkey\n",
		        key.c_str());
		return false;
	}

	// Friendly label for logs / mapper button
	out_label.clear();
	if (out_mods & PRIMARY_MOD) {
		out_label += PRIMARY_MOD_NAME;
		out_label += '+';
	}
	if (out_mods & MMOD2) {
		out_label += MMOD2_NAME;
		out_label += '+';
	}
	if (out_mods & MMOD3) {
		out_label += MMOD3_NAME;
		out_label += '+';
	}
	// uppercase key for display
	for (char c : key) {
		out_label.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
	}

	// Warn about known conflict
	if (out_key == SDL_SCANCODE_F9 && (out_mods & PRIMARY_MOD) &&
	    !(out_mods & ~PRIMARY_MOD)) {
		fprintf(stderr,
		        "[debugtrace] WARNING: ctrl+f9 is DOSBox Shutdown; "
		        "pick another screen_dump_hotkey\n");
	}

	return true;
}

} // namespace

void ScreenDump_Init(const ScreenDumpConfig& cfg)
{
	s_cfg   = cfg;
	s_ready = cfg.enabled;
	if (!s_ready) {
		return;
	}

	apply_mode(0x03);
	s_generation = 0;
	s_seq        = 0;
	s_game       = "GAME";

	if (!ensure_dir(s_cfg.dir)) {
		fprintf(stderr,
		        "[debugtrace] WARNING: screen_dump_dir '%s' not creatable\n",
		        s_cfg.dir.c_str());
	}

	SDL_Scancode key  = SDL_SCANCODE_UNKNOWN;
	uint32_t mods     = 0;
	std::string label = "none";
	const bool bind   = parse_hotkey(s_cfg.hotkey, key, mods, label);

	if (bind) {
		MAPPER_AddHandler(hotkey_handler, key, mods, "vramdump", "VRAM Dump");
	}

	fprintf(stderr,
	        "[debugtrace] screen dump enabled → dir='%s' on_mode_set=%s "
	        "delay_ms=%d hotkey=%s\n",
	        s_cfg.dir.c_str(),
	        s_cfg.on_mode_set ? "true" : "false",
	        s_cfg.on_mode_set_delay_ms,
	        bind ? label.c_str() : "disabled");
}

void ScreenDump_Shutdown()
{
	if (s_delay_pending) {
		PIC_RemoveEvents(delayed_dump_event);
		s_delay_pending = false;
	}
	s_ready = false;
}

void ScreenDump_SetGameName(const char* filename)
{
	s_game = sanitize_game_name(filename);
}

void ScreenDump_OnModeSet(const uint8_t mode_byte)
{
	if (!s_ready) {
		return;
	}
	++s_generation;
	apply_mode(mode_byte);
	schedule_or_dump_mode_set();
}

void ScreenDump_Hotkey(bool pressed)
{
	if (!pressed || !s_ready) {
		return;
	}
	write_dump_files("hotkey");
}

uint8_t ScreenDump_CurrentMode()
{
	return s_mode;
}
