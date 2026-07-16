// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Guest DS/phys memory dumps for reverse engineering (ICON stamps, MAP, etc.).

#include "mem_dump.h"
#include "game_trace.h"

#include "cpu/registers.h"
#include "gui/mapper.h"
#include "hardware/memory.h"

#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#	include <direct.h>
#	define MEM_DUMP_MKDIR(path) _mkdir(path)
#else
#	include <unistd.h>
#	define MEM_DUMP_MKDIR(path) mkdir((path), 0755)
#endif

namespace {

// ICON Quest defaults (see FORMAT-NOTES.md):
//   DS:207A  stamp bank BA‖BB  (192 × 24 = 0x1200)
//   DS:31D4  MAP index         (LA = 3840 = 0x0F00 used)
//   DS:206C  near ptr → offscreen text buffer (scroll step 0x1E0)
static constexpr const char* k_default_regions =
        "stamps@ds:207A+1200,map@ds:31D4+0F00,offscr@ds:206C->near+2000";

enum class RegionKind {
	FixedDs,   // phys = SegPhys(ds) + offset
	NearPtr,   // word near offset at ds:offset → SegPhys(ds)+word
	FarPtr,    // far ptr (off,seg) at ds:offset
	PhysAbs,   // absolute physical
};

struct Region {
	std::string name   = "";
	RegionKind  kind   = RegionKind::FixedDs;
	uint32_t    offset = 0; // DS offset or phys base
	uint32_t    size   = 0;
};

static MemDumpConfig s_cfg{};
static bool s_ready = false;
static std::string s_game = "GAME";
static uint32_t s_generation = 0;
static uint32_t s_seq        = 0;
static std::vector<Region> s_regions;

static bool ensure_dir(const std::string& path)
{
	if (path.empty() || path == "." || path == "./") {
		return true;
	}
	if (MEM_DUMP_MKDIR(path.c_str()) == 0) {
		return true;
	}
	struct stat st{};
	if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
		return true;
	}
	return false;
}

static std::string sanitize_game_name(const char* filename)
{
	if (!filename || !*filename) {
		return "GAME";
	}
	const char* base = filename;
	for (const char* p = filename; *p; ++p) {
		if (*p == '/' || *p == '\\' || *p == ':') {
			base = p + 1;
		}
	}
	std::string name(base);
	const auto dot = name.find_last_of('.');
	if (dot != std::string::npos) {
		name.resize(dot);
	}
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
	if (out.size() > 32) {
		out.resize(32);
	}
	return out;
}

static std::string sanitize_region_name(const std::string& in)
{
	std::string out;
	out.reserve(in.size());
	for (unsigned char c : in) {
		if (std::isalnum(c)) {
			out.push_back(static_cast<char>(std::tolower(c)));
		} else if (c == '-' || c == '_') {
			out.push_back('_');
		}
	}
	if (out.empty()) {
		out = "region";
	}
	if (out.size() > 24) {
		out.resize(24);
	}
	return out;
}

static uint32_t parse_hex(const std::string& s, bool& ok)
{
	ok = false;
	if (s.empty()) {
		return 0;
	}
	char* end = nullptr;
	const unsigned long v = strtoul(s.c_str(), &end, 16);
	if (end == s.c_str() || (end && *end != '\0')) {
		return 0;
	}
	ok = true;
	return static_cast<uint32_t>(v);
}

// Parse one region: name@ds:OFF+SIZE | name@ds:OFF->near+SIZE | name@ds:OFF->far+SIZE | name@phys:BASE+SIZE
static bool parse_one_region(const std::string& raw, Region& out)
{
	// strip spaces
	std::string s;
	s.reserve(raw.size());
	for (unsigned char c : raw) {
		if (c != ' ' && c != '\t') {
			s.push_back(static_cast<char>(c));
		}
	}
	if (s.empty()) {
		return false;
	}

	const auto at = s.find('@');
	if (at == std::string::npos || at == 0) {
		return false;
	}
	out.name = sanitize_region_name(s.substr(0, at));
	std::string rest = s.substr(at + 1);

	// lower for keyword match on prefix
	std::string rest_l = rest;
	for (char& c : rest_l) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	bool ok = false;
	if (rest_l.rfind("ds:", 0) == 0) {
		rest = rest.substr(3);
		// OFF+SIZE or OFF->near+SIZE or OFF->far+SIZE
		const auto arrow = rest.find("->");
		if (arrow != std::string::npos) {
			const std::string off_s = rest.substr(0, arrow);
			std::string tail = rest.substr(arrow + 2);
			// tail: near+SIZE or far+SIZE
			std::string tail_l = tail;
			for (char& c : tail_l) {
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}
			const auto plus = tail.find('+');
			if (plus == std::string::npos) {
				return false;
			}
			const std::string kind_s = tail_l.substr(0, plus);
			const std::string size_s = tail.substr(plus + 1);
			out.offset = parse_hex(off_s, ok);
			if (!ok) {
				return false;
			}
			out.size = parse_hex(size_s, ok);
			if (!ok || out.size == 0) {
				return false;
			}
			if (kind_s == "near") {
				out.kind = RegionKind::NearPtr;
			} else if (kind_s == "far") {
				out.kind = RegionKind::FarPtr;
			} else {
				return false;
			}
			return true;
		}
		const auto plus = rest.find('+');
		if (plus == std::string::npos) {
			return false;
		}
		out.kind   = RegionKind::FixedDs;
		out.offset = parse_hex(rest.substr(0, plus), ok);
		if (!ok) {
			return false;
		}
		out.size = parse_hex(rest.substr(plus + 1), ok);
		return ok && out.size > 0;
	}

	if (rest_l.rfind("phys:", 0) == 0) {
		rest = rest.substr(5);
		const auto plus = rest.find('+');
		if (plus == std::string::npos) {
			return false;
		}
		out.kind   = RegionKind::PhysAbs;
		out.offset = parse_hex(rest.substr(0, plus), ok);
		if (!ok) {
			return false;
		}
		out.size = parse_hex(rest.substr(plus + 1), ok);
		return ok && out.size > 0;
	}

	return false;
}

static void parse_regions(const std::string& spec)
{
	s_regions.clear();
	const std::string use = spec.empty() ? std::string(k_default_regions) : spec;

	size_t start = 0;
	while (start <= use.size()) {
		const size_t comma = use.find(',', start);
		const std::string part = (comma == std::string::npos)
		                                 ? use.substr(start)
		                                 : use.substr(start, comma - start);
		if (!part.empty()) {
			Region r;
			if (parse_one_region(part, r)) {
				if (r.size > 0x100000) {
					fprintf(stderr,
					        "[debugtrace] WARNING: mem_dump region '%s' size too large, clamped\n",
					        r.name.c_str());
					r.size = 0x100000;
				}
				s_regions.push_back(std::move(r));
			} else {
				fprintf(stderr,
				        "[debugtrace] WARNING: bad mem_dump_regions entry '%s'\n",
				        part.c_str());
			}
		}
		if (comma == std::string::npos) {
			break;
		}
		start = comma + 1;
	}

	if (s_regions.empty()) {
		fprintf(stderr,
		        "[debugtrace] WARNING: no valid mem_dump regions; using ICON defaults\n");
		// force defaults
		Region r;
		if (parse_one_region("stamps@ds:207A+1200", r)) {
			s_regions.push_back(r);
		}
		if (parse_one_region("map@ds:31D4+0F00", r)) {
			s_regions.push_back(r);
		}
		if (parse_one_region("offscr@ds:206C->near+2000", r)) {
			s_regions.push_back(r);
		}
	}
}

static bool resolve_region(const Region& r, uint32_t& out_base, uint32_t& out_size,
                           std::string& detail)
{
	out_size = r.size;
	char buf[128];
	const uint16_t ds_val = SegValue(ds);

	switch (r.kind) {
	case RegionKind::FixedDs: {
		out_base = SegPhys(ds) + r.offset;
		snprintf(buf, sizeof(buf), "ds:%04X:%04X", static_cast<unsigned>(ds_val),
		         static_cast<unsigned>(r.offset));
		detail = buf;
		return true;
	}
	case RegionKind::NearPtr: {
		const uint32_t ptr_phys = SegPhys(ds) + r.offset;
		const uint16_t near_off = mem_readw(ptr_phys);
		out_base = SegPhys(ds) + near_off;
		snprintf(buf, sizeof(buf),
		         "near*[ds:%04X:%04X]=%04X -> ds:%04X:%04X",
		         static_cast<unsigned>(ds_val), static_cast<unsigned>(r.offset),
		         static_cast<unsigned>(near_off), static_cast<unsigned>(ds_val),
		         static_cast<unsigned>(near_off));
		detail = buf;
		return true;
	}
	case RegionKind::FarPtr: {
		const uint32_t ptr_phys = SegPhys(ds) + r.offset;
		const uint16_t off = mem_readw(ptr_phys);
		const uint16_t seg = mem_readw(ptr_phys + 2);
		out_base = (static_cast<uint32_t>(seg) << 4) + off;
		snprintf(buf, sizeof(buf), "far*[ds:%04X:%04X]=%04X:%04X -> phys %05X",
		         static_cast<unsigned>(ds_val), static_cast<unsigned>(r.offset),
		         static_cast<unsigned>(seg), static_cast<unsigned>(off),
		         static_cast<unsigned>(out_base));
		detail = buf;
		return true;
	}
	case RegionKind::PhysAbs: {
		out_base = r.offset;
		snprintf(buf, sizeof(buf), "phys:%05X", static_cast<unsigned>(out_base));
		detail = buf;
		return true;
	}
	}
	return false;
}

static void write_one_region(const Region& r, const char* reason)
{
	uint32_t base = 0;
	uint32_t size = 0;
	std::string detail;
	if (!resolve_region(r, base, size, detail) || size == 0) {
		return;
	}

	++s_seq;
	char stem[320];
	snprintf(stem, sizeof(stem), "%s_mem_g%04u_%s_b%05X_s%04X_%04u",
	         s_game.c_str(), static_cast<unsigned>(s_generation), r.name.c_str(),
	         static_cast<unsigned>(base), static_cast<unsigned>(size),
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
		buf[i] = mem_readb(base + i);
	}

	FILE* fp = fopen(bin_path.c_str(), "wb");
	if (!fp) {
		fprintf(stderr, "[debugtrace] WARNING: cannot write mem dump '%s'\n",
		        bin_path.c_str());
		return;
	}
	const size_t nw = fwrite(buf.data(), 1, size, fp);
	fclose(fp);
	if (nw != size) {
		fprintf(stderr, "[debugtrace] WARNING: short write on '%s' (%zu/%u)\n",
		        bin_path.c_str(), nw, static_cast<unsigned>(size));
	}

	if (s_cfg.write_meta) {
		FILE* mf = fopen(meta_path.c_str(), "w");
		if (mf) {
			fprintf(mf, "game=%s\n", s_game.c_str());
			fprintf(mf, "reason=%s\n", reason ? reason : "");
			fprintf(mf, "generation=%u\n", static_cast<unsigned>(s_generation));
			fprintf(mf, "seq=%u\n", static_cast<unsigned>(s_seq));
			fprintf(mf, "name=%s\n", r.name.c_str());
			fprintf(mf, "base=0x%05X\n", static_cast<unsigned>(base));
			fprintf(mf, "size=0x%04X\n", static_cast<unsigned>(size));
			fprintf(mf, "ds=0x%04X\n", static_cast<unsigned>(SegValue(ds)));
			fprintf(mf, "resolve=%s\n", detail.c_str());
			fprintf(mf, "t_ms=%" PRIu64 "\n", DEBUGTRACE_GetElapsedMs());
			fclose(mf);
		}
	}

	if (g_trace_enabled || g_debugtrace_system_ready) {
		char line[640];
		snprintf(line, sizeof(line),
		         "[T+%08" PRIu64 "ms] MEM DUMP: %s (%u bytes) %s reason=%s",
		         DEBUGTRACE_GetElapsedMs(), bin_path.c_str(),
		         static_cast<unsigned>(size), detail.c_str(),
		         reason ? reason : "");
		DEBUGTRACE_Write(line);
	} else {
		fprintf(stderr, "[debugtrace] MEM DUMP: %s (%u bytes)\n", bin_path.c_str(),
		        static_cast<unsigned>(size));
	}
}

static void write_all_regions(const char* reason)
{
	if (!s_ready || !s_cfg.enabled) {
		return;
	}
	if (!ensure_dir(s_cfg.dir)) {
		fprintf(stderr, "[debugtrace] WARNING: cannot create mem dump dir '%s'\n",
		        s_cfg.dir.c_str());
		return;
	}
	for (const auto& r : s_regions) {
		write_one_region(r, reason);
	}
}

static void hotkey_handler(bool pressed)
{
	if (!pressed) {
		return;
	}
	MemDump_Hotkey(true);
}

// Same grammar as screen_dump hotkey parser (ctrl+f11, etc.)
static bool parse_hotkey(const std::string& spec_in, SDL_Scancode& out_key,
                         uint32_t& out_mods, std::string& out_label)
{
	out_key  = SDL_SCANCODE_UNKNOWN;
	out_mods = 0;
	out_label.clear();

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

	const std::string key = parts.back();
	for (size_t i = 0; i + 1 < parts.size(); ++i) {
		const auto& m = parts[i];
		if (m == "ctrl" || m == "control" || m == "primary") {
			out_mods |= PRIMARY_MOD;
		} else if (m == "alt" || m == "opt") {
			out_mods |= MMOD2;
		} else if (m == "shift") {
			fprintf(stderr,
			        "[debugtrace] WARNING: 'shift' is not supported in "
			        "mem_dump_hotkey; ignoring\n");
		} else if (m == "gui" || m == "win" || m == "super" || m == "cmd" ||
		           m == "meta") {
			out_mods |= MMOD3;
		} else {
			fprintf(stderr,
			        "[debugtrace] WARNING: unknown modifier '%s' in "
			        "mem_dump_hotkey\n",
			        m.c_str());
			return false;
		}
	}

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
		        "[debugtrace] WARNING: unknown key '%s' in mem_dump_hotkey\n",
		        key.c_str());
		return false;
	}

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
	for (char c : key) {
		out_label.push_back(
		        static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
	}

	if (out_key == SDL_SCANCODE_F9 && (out_mods & PRIMARY_MOD) &&
	    !(out_mods & ~PRIMARY_MOD)) {
		fprintf(stderr,
		        "[debugtrace] WARNING: ctrl+f9 is DOSBox Shutdown; "
		        "pick another mem_dump_hotkey\n");
	}

	return true;
}

} // namespace

void MemDump_Init(const MemDumpConfig& cfg)
{
	s_cfg   = cfg;
	s_ready = cfg.enabled;
	if (!s_ready) {
		return;
	}

	s_generation = 0;
	s_seq        = 0;
	s_game       = "GAME";
	parse_regions(s_cfg.regions);

	if (!ensure_dir(s_cfg.dir)) {
		fprintf(stderr, "[debugtrace] WARNING: mem_dump_dir '%s' not creatable\n",
		        s_cfg.dir.c_str());
	}

	SDL_Scancode key  = SDL_SCANCODE_UNKNOWN;
	uint32_t mods     = 0;
	std::string label = "none";
	const bool bind   = parse_hotkey(s_cfg.hotkey, key, mods, label);

	if (bind) {
		MAPPER_AddHandler(hotkey_handler, key, mods, "memdump", "Mem Dump");
	}

	fprintf(stderr,
	        "[debugtrace] mem dump enabled → dir='%s' regions=%zu hotkey=%s\n",
	        s_cfg.dir.c_str(), s_regions.size(),
	        bind ? label.c_str() : "disabled");
}

void MemDump_Shutdown()
{
	s_ready = false;
	s_regions.clear();
}

void MemDump_SetGameName(const char* filename)
{
	s_game = sanitize_game_name(filename);
}

void MemDump_OnModeSet(const uint8_t /*mode_byte*/)
{
	if (!s_ready) {
		return;
	}
	++s_generation;
}

void MemDump_Hotkey(bool pressed)
{
	if (!pressed || !s_ready) {
		return;
	}
	write_all_regions("hotkey");
}
