// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// UNIX domain socket control plane for direct key injection + text world view.
// Designed for agents: no X11/xdotool. Key mapping mirrors keypress --emulator-mode.

#include "control_socket.h"

#include "config/setup.h"
#include "hardware/input/keyboard.h"
#include "hardware/memory.h"
#include "debug_trace/screen_dump.h"
#include "debug_trace/mem_dump.h"
#include "gui/debug_overlay.h"
#include "gui/common.h"
#include "capture/capture.h"
#include "debug_trace/game_trace.h"
#include "debug_trace/cpu_backlog.h"
#include "debug_trace/agent_re.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef WIN32
#	include <sys/socket.h>
#	include <sys/types.h>
#	include <sys/un.h>
#	include <unistd.h>
#	include <fcntl.h>
#	include <poll.h>
#	include <signal.h>
#endif

#include "misc/logging.h"

namespace {

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

struct Cfg {
	bool enabled       = false;
	std::string path   = "/tmp/dosbox-control.sock";
	// empty → derive from path (.sock → .pid, else path + ".pid")
	// "none" / "off" / "false" → do not write a pid file
	std::string pidfile;
	// hold duration for KEY (press+release) in milliseconds
	int key_hold_ms    = 30;
};

static Cfg g_cfg{};
static std::atomic<bool> g_running{false};
static std::thread g_accept_thread;
static int g_listen_fd = -1;
static std::string g_pidfile_written; // actual path written (for cleanup)

// ---------------------------------------------------------------------------
// Key mapping (keypress.py US / emulator-mode → KBD_*)
// ---------------------------------------------------------------------------

static KBD_KEYS letter_to_kbd(const char c)
{
	switch (std::tolower(static_cast<unsigned char>(c))) {
	case 'a': return KBD_a;
	case 'b': return KBD_b;
	case 'c': return KBD_c;
	case 'd': return KBD_d;
	case 'e': return KBD_e;
	case 'f': return KBD_f;
	case 'g': return KBD_g;
	case 'h': return KBD_h;
	case 'i': return KBD_i;
	case 'j': return KBD_j;
	case 'k': return KBD_k;
	case 'l': return KBD_l;
	case 'm': return KBD_m;
	case 'n': return KBD_n;
	case 'o': return KBD_o;
	case 'p': return KBD_p;
	case 'q': return KBD_q;
	case 'r': return KBD_r;
	case 's': return KBD_s;
	case 't': return KBD_t;
	case 'u': return KBD_u;
	case 'v': return KBD_v;
	case 'w': return KBD_w;
	case 'x': return KBD_x;
	case 'y': return KBD_y;
	case 'z': return KBD_z;
	default: return KBD_NONE;
	}
}

static KBD_KEYS digit_to_kbd(const char c)
{
	switch (c) {
	case '0': return KBD_0;
	case '1': return KBD_1;
	case '2': return KBD_2;
	case '3': return KBD_3;
	case '4': return KBD_4;
	case '5': return KBD_5;
	case '6': return KBD_6;
	case '7': return KBD_7;
	case '8': return KBD_8;
	case '9': return KBD_9;
	default: return KBD_NONE;
	}
}

// name is already lowercased
static bool name_to_kbd(const std::string& name, KBD_KEYS& key, bool& shift)
{
	shift = false;
	if (name.empty()) {
		return false;
	}

	// Single character (US emulator layout)
	if (name.size() == 1) {
		const char c = name[0];
		if (c >= 'a' && c <= 'z') {
			key   = letter_to_kbd(c);
			shift = false;
			return key != KBD_NONE;
		}
		if (c >= 'A' && c <= 'Z') {
			key   = letter_to_kbd(c);
			shift = true;
			return key != KBD_NONE;
		}
		if (c >= '0' && c <= '9') {
			key   = digit_to_kbd(c);
			shift = false;
			return key != KBD_NONE;
		}
		// US unshifted symbols
		static const std::unordered_map<char, KBD_KEYS> sym = {
		        {' ', KBD_space},  {'-', KBD_minus},  {'=', KBD_equals},
		        {'[', KBD_leftbracket}, {']', KBD_rightbracket},
		        {'\\', KBD_backslash}, {';', KBD_semicolon},
		        {'\'', KBD_quote}, {'`', KBD_grave},
		        {',', KBD_comma}, {'.', KBD_period}, {'/', KBD_slash},
		};
		// shifted number row
		static const std::unordered_map<char, std::pair<KBD_KEYS, bool>> shift_sym = {
		        {'!', {KBD_1, true}},  {'@', {KBD_2, true}},  {'#', {KBD_3, true}},
		        {'$', {KBD_4, true}},  {'%', {KBD_5, true}},  {'^', {KBD_6, true}},
		        {'&', {KBD_7, true}},  {'*', {KBD_8, true}},  {'(', {KBD_9, true}},
		        {')', {KBD_0, true}},  {'_', {KBD_minus, true}}, {'+', {KBD_equals, true}},
		        {'{', {KBD_leftbracket, true}}, {'}', {KBD_rightbracket, true}},
		        {'|', {KBD_backslash, true}}, {':', {KBD_semicolon, true}},
		        {'"', {KBD_quote, true}}, {'~', {KBD_grave, true}},
		        {'<', {KBD_comma, true}}, {'>', {KBD_period, true}},
		        {'?', {KBD_slash, true}},
		};
		auto it = sym.find(c);
		if (it != sym.end()) {
			key   = it->second;
			shift = false;
			return true;
		}
		auto it2 = shift_sym.find(c);
		if (it2 != shift_sym.end()) {
			key   = it2->second.first;
			shift = it2->second.second;
			return true;
		}
		return false;
	}

	// Named keys (case-insensitive; name already lower)
	static const std::unordered_map<std::string, KBD_KEYS> named = {
	        {"space", KBD_space},
	        {"esc", KBD_esc},
	        {"escape", KBD_esc},
	        {"enter", KBD_enter},
	        {"return", KBD_enter},
	        {"tab", KBD_tab},
	        {"backspace", KBD_backspace},
	        {"bksp", KBD_backspace},
	        {"up", KBD_up},
	        {"down", KBD_down},
	        {"left", KBD_left},
	        {"right", KBD_right},
	        {"f1", KBD_f1},  {"f2", KBD_f2},  {"f3", KBD_f3},  {"f4", KBD_f4},
	        {"f5", KBD_f5},  {"f6", KBD_f6},  {"f7", KBD_f7},  {"f8", KBD_f8},
	        {"f9", KBD_f9},  {"f10", KBD_f10}, {"f11", KBD_f11}, {"f12", KBD_f12},
	        {"home", KBD_home},
	        {"end", KBD_end},
	        {"pageup", KBD_pageup},
	        {"pgup", KBD_pageup},
	        {"pagedown", KBD_pagedown},
	        {"pgdn", KBD_pagedown},
	        {"insert", KBD_insert},
	        {"ins", KBD_insert},
	        {"delete", KBD_delete},
	        {"del", KBD_delete},
	        {"lshift", KBD_leftshift},
	        {"leftshift", KBD_leftshift},
	        {"shift", KBD_leftshift},
	        {"rshift", KBD_rightshift},
	        {"rightshift", KBD_rightshift},
	        {"lctrl", KBD_leftctrl},
	        {"leftctrl", KBD_leftctrl},
	        {"ctrl", KBD_leftctrl},
	        {"control", KBD_leftctrl},
	        {"rctrl", KBD_rightctrl},
	        {"rightctrl", KBD_rightctrl},
	        {"lalt", KBD_leftalt},
	        {"leftalt", KBD_leftalt},
	        {"alt", KBD_leftalt},
	        {"ralt", KBD_rightalt},
	        {"rightalt", KBD_rightalt},
	        // Keypad (ICON F1 movement rose)
	        {"kp0", KBD_kp0}, {"kp_0", KBD_kp0},
	        {"kp1", KBD_kp1}, {"kp_1", KBD_kp1},
	        {"kp2", KBD_kp2}, {"kp_2", KBD_kp2}, {"kpdown", KBD_kp2},
	        {"kp3", KBD_kp3}, {"kp_3", KBD_kp3},
	        {"kp4", KBD_kp4}, {"kp_4", KBD_kp4}, {"kpleft", KBD_kp4},
	        {"kp5", KBD_kp5}, {"kp_5", KBD_kp5},
	        {"kp6", KBD_kp6}, {"kp_6", KBD_kp6}, {"kpright", KBD_kp6},
	        {"kp7", KBD_kp7}, {"kp_7", KBD_kp7},
	        {"kp8", KBD_kp8}, {"kp_8", KBD_kp8}, {"kpup", KBD_kp8},
	        {"kp9", KBD_kp9}, {"kp_9", KBD_kp9},
	        {"kpenter", KBD_kpenter},
	};

	const auto it = named.find(name);
	if (it != named.end()) {
		key   = it->second;
		shift = false;
		return true;
	}
	return false;
}

static std::string lower_copy(std::string s)
{
	for (auto& c : s) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return s;
}

// ---------------------------------------------------------------------------
// Pidfile helpers (Unix only; no-ops used from Init under #ifndef WIN32)
// ---------------------------------------------------------------------------

#ifndef WIN32

static std::string derive_pidfile(const std::string& sock_path)
{
	const auto pos = sock_path.rfind(".sock");
	if (pos != std::string::npos && pos + 5 == sock_path.size()) {
		return sock_path.substr(0, pos) + ".pid";
	}
	return sock_path + ".pid";
}

// Empty config → auto-derive. Explicit "none"/"off"/"false"/"0" → disabled.
static std::string resolve_pidfile_path(const std::string& configured,
                                        const std::string& sock_path)
{
	const auto low = lower_copy(configured);
	if (low == "none" || low == "off" || low == "false" || low == "0") {
		return {};
	}
	if (configured.empty() || low == "auto") {
		return derive_pidfile(sock_path);
	}
	return configured;
}

static bool pid_is_alive(const pid_t pid)
{
	if (pid <= 0) {
		return false;
	}
	return kill(pid, 0) == 0 || errno == EPERM;
}

static pid_t read_pidfile(const std::string& path)
{
	FILE* f = fopen(path.c_str(), "r");
	if (!f) {
		return 0;
	}
	long v = 0;
	if (std::fscanf(f, "%ld", &v) != 1) {
		fclose(f);
		return 0;
	}
	fclose(f);
	return static_cast<pid_t>(v);
}

static bool write_pidfile(const std::string& path)
{
	FILE* f = fopen(path.c_str(), "w");
	if (!f) {
		LOG_ERR("CONTROL_SOCKET: cannot write pidfile %s: %s",
		        path.c_str(),
		        strerror(errno));
		return false;
	}
	std::fprintf(f, "%d\n", static_cast<int>(getpid()));
	fclose(f);
	return true;
}

// True if something is actually accepting on the UNIX socket.
static bool socket_is_live(const std::string& sock_path)
{
	const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	sockaddr_un addr{};
	addr.sun_family = AF_UNIX;
	if (sock_path.size() >= sizeof(addr.sun_path)) {
		close(fd);
		return false;
	}
	std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path.c_str());
	const int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	if (rc == 0) {
		close(fd);
		return true;
	}
	close(fd);
	return false;
}

// Remove leftover socket/pidfile if previous owner is dead / sock not listening.
// Refuse only if another process is actually accepting on the path.
static bool clean_stale_socket(const std::string& sock_path,
                              const std::string& pid_path)
{
	if (access(sock_path.c_str(), F_OK) != 0) {
		if (!pid_path.empty() && access(pid_path.c_str(), F_OK) == 0) {
			const pid_t old = read_pidfile(pid_path);
			if (!pid_is_alive(old) || old == getpid()) {
				unlink(pid_path.c_str());
			}
		}
		return true;
	}

	// Prefer connect() over kill(pid): pidfiles can point at re-used PIDs
	// (e.g. 1) while the socket is dead → would block rebinding forever.
	if (socket_is_live(sock_path)) {
		const pid_t old = pid_path.empty() ? 0 : read_pidfile(pid_path);
		if (old > 0) {
			LOG_ERR("CONTROL_SOCKET: %s already in use by pid %d",
			        sock_path.c_str(),
			        static_cast<int>(old));
		} else {
			LOG_ERR("CONTROL_SOCKET: %s already in use", sock_path.c_str());
		}
		return false;
	}

	if (unlink(sock_path.c_str()) != 0 && errno != ENOENT) {
		LOG_ERR("CONTROL_SOCKET: unlink(%s) failed: %s",
		        sock_path.c_str(),
		        strerror(errno));
		return false;
	}
	if (!pid_path.empty()) {
		unlink(pid_path.c_str());
	}
	return true;
}

#endif // !WIN32

// ---------------------------------------------------------------------------
// Command queue (main-thread execution, like Webserver::DebugBridge)
// ---------------------------------------------------------------------------

enum class CmdKind {
	KeyTap,    // press+release (optional shift)
	KeyDown,
	KeyUp,
	TypeText,  // each char as tap
	GetText,   // ANSI/ASCII lines of VRAM
	GetB800,   // hex dump of visible page
	Ping,
	Status,    // pid + socket path (no guest state needed)
	DumpScreen, // trigger ScreenDump_Hotkey
	DumpMem,    // trigger MemDump_Hotkey
	CaptureShot, // Staging PNG capture (grouped/rendered/raw)
	TraceToggle, // DEBUGTRACE_ToggleActive
	Traceback,   // CpuBacklog_FormatTraceback
	AgentCmd,    // AgentRe_Cmd / SNAPSHOT / DIFF
};

struct Command {
	CmdKind kind = CmdKind::Ping;
	std::string arg;
	KBD_KEYS key = KBD_NONE;
	bool shift   = false;

	// Filled on main thread
	std::string reply;
	bool done = false;
};

static std::mutex g_mtx;
static std::condition_variable g_cv;
static std::deque<Command*> g_queue;

static void queue_and_wait(Command& cmd, const uint32_t timeout_ms = 2000)
{
	std::unique_lock<std::mutex> lock(g_mtx);
	cmd.done = false;
	g_queue.push_back(&cmd);
	const bool ok = g_cv.wait_for(lock,
	                              std::chrono::milliseconds(timeout_ms),
	                              [&] { return cmd.done; });
	if (!ok) {
		// remove if still pending
		for (auto it = g_queue.begin(); it != g_queue.end(); ++it) {
			if (*it == &cmd) {
				g_queue.erase(it);
				break;
			}
		}
		cmd.reply = "ERR timeout\n";
	}
}

static void key_tap(const KBD_KEYS key, const bool with_shift, const int hold_ms)
{
	if (key == KBD_NONE) {
		return;
	}
	if (with_shift) {
		KEYBOARD_AddKey(KBD_leftshift, true);
	}
	KEYBOARD_AddKey(key, true);
	// busy wait is bad; short PIC-friendly delay via sleep is ok on main thread
	if (hold_ms > 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
	}
	KEYBOARD_AddKey(key, false);
	if (with_shift) {
		KEYBOARD_AddKey(KBD_leftshift, false);
	}
}

// CP437 printable-ish → ASCII for agent TEXT view
static char cp437_to_ascii(const uint8_t ch)
{
	if (ch >= 32 && ch < 127) {
		return static_cast<char>(ch);
	}
	// keep a few game-relevant glyphs as distinct stand-ins
	switch (ch) {
	case 0x1E: return '^'; // up triangle
	case 0x1F: return 'v'; // down triangle (hero hurt marker)
	case 0x02: return '@'; // face-ish
	case 0x2A: return '*';
	case 0xB0: return ':';
	case 0xB1: return '#';
	case 0xB2: return '#';
	case 0xDB: return '#';
	case 0xDE: return '.'; // half-block floor often
	case 0x00: return ' ';
	default: return '.';
	}
}

static void execute_on_main(Command& cmd)
{
	const int hold = g_cfg.key_hold_ms;

	switch (cmd.kind) {
	case CmdKind::Ping:
		cmd.reply = "OK PONG\n";
		break;

	case CmdKind::Status: {
#ifndef WIN32
		int oc = 0;
		int orows = 0;
		DEBUG_OVERLAY_GetGrid(oc, orows);
		cmd.reply = "OK pid=" + std::to_string(static_cast<int>(getpid())) +
		            " sock=" + g_cfg.path +
		            " pidfile=" +
		            (g_pidfile_written.empty() ? std::string("none")
		                                       : g_pidfile_written) +
		            " hold_ms=" + std::to_string(g_cfg.key_hold_ms) +
		            " overlay=" +
		            (DEBUG_OVERLAY_IsEnabled() ? "on" : "off") +
		            " grid=" + std::to_string(oc) + "x" +
		            std::to_string(orows) + "\n";
#else
		cmd.reply = "OK pid=0 sock=disabled\n";
#endif
		break;
	}

	case CmdKind::KeyTap:
		if (cmd.key == KBD_NONE) {
			cmd.reply = "ERR unknown key\n";
			break;
		}
		key_tap(cmd.key, cmd.shift, hold);
		cmd.reply = "OK\n";
		break;

	case CmdKind::KeyDown:
		if (cmd.key == KBD_NONE) {
			cmd.reply = "ERR unknown key\n";
			break;
		}
		if (cmd.shift) {
			KEYBOARD_AddKey(KBD_leftshift, true);
		}
		KEYBOARD_AddKey(cmd.key, true);
		cmd.reply = "OK\n";
		break;

	case CmdKind::KeyUp:
		if (cmd.key == KBD_NONE) {
			cmd.reply = "ERR unknown key\n";
			break;
		}
		KEYBOARD_AddKey(cmd.key, false);
		if (cmd.shift) {
			KEYBOARD_AddKey(KBD_leftshift, false);
		}
		cmd.reply = "OK\n";
		break;

	case CmdKind::TypeText: {
		for (const char c : cmd.arg) {
			KBD_KEYS k = KBD_NONE;
			bool sh    = false;
			std::string one(1, c);
			// keep case for shift
			if (!name_to_kbd(std::string(1, c), k, sh)) {
				// try lower for letters already handled
				if (!name_to_kbd(lower_copy(one), k, sh) && c != '\r' &&
				    c != '\n') {
					continue;
				}
			}
			// re-parse with original case for A-Z
			if (c >= 'A' && c <= 'Z') {
				k  = letter_to_kbd(c);
				sh = true;
			} else if (c >= 'a' && c <= 'z') {
				k  = letter_to_kbd(c);
				sh = false;
			}
			if (k != KBD_NONE) {
				key_tap(k, sh, hold);
			}
		}
		cmd.reply = "OK\n";
		break;
	}

	case CmdKind::GetText: {
		// Visible text page: mode-dependent size via ScreenDump helpers
		const uint8_t mode = ScreenDump_CurrentMode();
		uint16_t cols      = 80;
		uint16_t rows      = 25;
		uint32_t base      = 0xB8000;
		if (mode == 0x00 || mode == 0x01) {
			cols = 40;
			rows = 25;
		} else if (mode == 0x07) {
			base = 0xB0000;
		}
		std::string out = "OK TEXT " + std::to_string(cols) + "x" +
		                  std::to_string(rows) + " mode=" +
		                  std::to_string(mode) + "\n";
		for (uint16_t y = 0; y < rows; ++y) {
			for (uint16_t x = 0; x < cols; ++x) {
				const uint32_t off = (static_cast<uint32_t>(y) * cols +
				                      x) *
				                     2;
				const uint8_t ch = mem_readb(base + off);
				out.push_back(cp437_to_ascii(ch));
			}
			out.push_back('\n');
		}
		out += "END\n";
		cmd.reply = std::move(out);
		break;
	}

	case CmdKind::GetB800: {
		const uint8_t mode = ScreenDump_CurrentMode();
		uint32_t base      = 0xB8000;
		uint32_t size      = 0x0FA0; // 80x25
		if (mode == 0x00 || mode == 0x01) {
			size = 0x07D0; // 40x25
		} else if (mode == 0x07) {
			base = 0xB0000;
		}
		std::string out = "OK B800 size=" + std::to_string(size) +
		                  " base=" + std::to_string(base) + "\n";
		static const char* hexd = "0123456789abcdef";
		out.reserve(out.size() + size * 2 + 8);
		for (uint32_t i = 0; i < size; ++i) {
			const uint8_t b = mem_readb(base + i);
			out.push_back(hexd[b >> 4]);
			out.push_back(hexd[b & 0xf]);
		}
		out += "\nEND\n";
		cmd.reply = std::move(out);
		break;
	}

	case CmdKind::DumpScreen:
		ScreenDump_Hotkey(true);
		ScreenDump_Hotkey(false);
		cmd.reply = "OK\n";
		break;

	case CmdKind::DumpMem:
		MemDump_Hotkey(true);
		MemDump_Hotkey(false);
		cmd.reply = "OK\n";
		break;

	case CmdKind::CaptureShot: {
		// arg: grouped | rendered | raw (default grouped = Ctrl+F5 style)
		const std::string mode = lower_copy(cmd.arg);
		if (mode.empty() || mode == "grouped" || mode == "default" ||
		    mode == "f5") {
			CAPTURE_RequestGroupedScreenshot();
			cmd.reply = "OK capture=grouped\n";
		} else if (mode == "rendered" || mode == "altf5") {
			CAPTURE_RequestRenderedScreenshot();
			cmd.reply = "OK capture=rendered\n";
		} else if (mode == "raw") {
			CAPTURE_RequestRawScreenshot();
			cmd.reply = "OK capture=raw\n";
		} else {
			cmd.reply = "ERR capture mode (grouped|rendered|raw)\n";
		}
		break;
	}

	case CmdKind::TraceToggle:
		DEBUGTRACE_ToggleActive();
		cmd.reply = std::string("OK trace=") +
		            (DEBUGTRACE_IsActive() ? "on" : "off") +
		            " user=" +
		            (DEBUGTRACE_UserWantsActive() ? "on" : "off") + "\n";
		break;

	case CmdKind::Traceback: {
		int n = 0;
		if (!cmd.arg.empty()) {
			try {
				n = std::stoi(cmd.arg);
			} catch (...) {
				n = 0;
			}
		}
		// Must run on main thread (reads live CPU regs for NOW= block).
		cmd.reply = CpuBacklog_FormatTraceback(n);
		break;
	}

	case CmdKind::AgentCmd: {
		// arg is full agent command line (e.g. "BP foo 1234:5678")
		const std::string& a = cmd.arg;
		const auto sp        = a.find(' ');
		const std::string head = (sp == std::string::npos)
		                                 ? lower_copy(a)
		                                 : lower_copy(a.substr(0, sp));
		const std::string rest = (sp == std::string::npos) ? std::string()
		                                                   : a.substr(sp + 1);
		if (head == "snapshot") {
			cmd.reply = AgentRe_Snapshot(rest);
		} else if (head == "diff") {
			auto toks = rest;
			std::string ta;
			std::string tb;
			const auto p = rest.find(' ');
			if (p == std::string::npos) {
				cmd.reply = "ERR usage: DIFF <tagA> <tagB>\n";
			} else {
				ta = rest.substr(0, p);
				tb = rest.substr(p + 1);
				while (!tb.empty() && tb.front() == ' ') {
					tb.erase(tb.begin());
				}
				cmd.reply = AgentRe_Diff(ta, tb);
			}
		} else if (head == "traceback" || head == "jsontraceback") {
			int n = 0;
			if (!rest.empty()) {
				try {
					n = std::stoi(rest);
				} catch (...) {
					n = 0;
				}
			}
			// Text TRACEBACK; agent can parse. JSON optional later.
			cmd.reply = CpuBacklog_FormatTraceback(n);
		} else {
			cmd.reply = AgentRe_Cmd(a);
		}
		break;
	}
	}
}

// ---------------------------------------------------------------------------
// Client I/O helpers
// ---------------------------------------------------------------------------

#ifndef WIN32

static bool send_all(const int fd, const std::string& s)
{
	size_t off = 0;
	while (off < s.size()) {
		const ssize_t n = write(fd, s.data() + off, s.size() - off);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		off += static_cast<size_t>(n);
	}
	return true;
}

static bool read_line(const int fd, std::string& line)
{
	line.clear();
	char c = 0;
	while (true) {
		const ssize_t n = read(fd, &c, 1);
		if (n == 0) {
			return false; // EOF
		}
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (c == '\n') {
			return true;
		}
		if (c != '\r') {
			line.push_back(c);
		}
		if (line.size() > 8192) {
			return false;
		}
	}
}

static std::string handle_line(const std::string& raw)
{
	// Trim
	std::string line = raw;
	while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
		line.pop_back();
	}
	if (line.empty()) {
		return "OK\n";
	}

	// Split first word
	std::string cmd;
	std::string rest;
	const auto sp = line.find(' ');
	if (sp == std::string::npos) {
		cmd = line;
	} else {
		cmd  = line.substr(0, sp);
		rest = line.substr(sp + 1);
		while (!rest.empty() && rest.front() == ' ') {
			rest.erase(rest.begin());
		}
	}
	const std::string cmd_l = lower_copy(cmd);

	Command c{};
	if (cmd_l == "ping" || cmd_l == "hello") {
		c.kind = CmdKind::Ping;
		if (cmd_l == "hello") {
			// answer immediately without queue? still use queue for consistency
		}
	} else if (cmd_l == "key" || cmd_l == "tap") {
		c.kind = CmdKind::KeyTap;
		// rest may be multi-token: "leftshift" or "P" or "kp2"
		// support KEY name OR KEY name1+name2 for combos later
		std::string kname = lower_copy(rest);
		// preserve shift for single capital letter: if rest is "P" keep shift
		bool shift = false;
		KBD_KEYS k = KBD_NONE;
		if (rest.size() == 1 && rest[0] >= 'A' && rest[0] <= 'Z') {
			k     = letter_to_kbd(rest[0]);
			shift = true;
		} else if (!name_to_kbd(kname, k, shift)) {
			return "ERR unknown key '" + rest + "'\n";
		}
		c.key   = k;
		c.shift = shift;
	} else if (cmd_l == "keydown" || cmd_l == "down") {
		c.kind = CmdKind::KeyDown;
		bool shift = false;
		KBD_KEYS k = KBD_NONE;
		if (!name_to_kbd(lower_copy(rest), k, shift) &&
		    !(rest.size() == 1 &&
		      (k = letter_to_kbd(rest[0]), k != KBD_NONE))) {
			return "ERR unknown key\n";
		}
		if (rest.size() == 1 && rest[0] >= 'A' && rest[0] <= 'Z') {
			k     = letter_to_kbd(rest[0]);
			shift = true;
		}
		c.key   = k;
		c.shift = shift;
	} else if (cmd_l == "keyup" || cmd_l == "up") {
		c.kind = CmdKind::KeyUp;
		bool shift = false;
		KBD_KEYS k = KBD_NONE;
		if (!name_to_kbd(lower_copy(rest), k, shift) &&
		    !(rest.size() == 1 &&
		      (k = letter_to_kbd(rest[0]), k != KBD_NONE))) {
			return "ERR unknown key\n";
		}
		c.key   = k;
		c.shift = shift;
	} else if (cmd_l == "type") {
		c.kind = CmdKind::TypeText;
		c.arg  = rest;
	} else if (cmd_l == "text" || cmd_l == "gettext") {
		c.kind = CmdKind::GetText;
	} else if (cmd_l == "b800" || cmd_l == "getb800") {
		c.kind = CmdKind::GetB800;
	} else if (cmd_l == "dumpscreen" || cmd_l == "screen_dump") {
		c.kind = CmdKind::DumpScreen;
	} else if (cmd_l == "dumpmem" || cmd_l == "mem_dump") {
		c.kind = CmdKind::DumpMem;
	} else if (cmd_l == "status") {
		c.kind = CmdKind::Status;
	} else if (cmd_l == "overlay") {
		// Host-side grid only — never touches guest VRAM.
		const std::string arg = lower_copy(rest);
		if (arg.empty() || arg == "status" || arg == "?") {
			int oc = 0;
			int orows = 0;
			DEBUG_OVERLAY_GetGrid(oc, orows);
			return "OK overlay=" +
			       std::string(DEBUG_OVERLAY_IsEnabled() ? "on" : "off") +
			       " grid=" + std::to_string(oc) + "x" +
			       std::to_string(orows) +
			       " (host-only; VRAM dumps pure)\n";
		}
		if (arg == "on" || arg == "1" || arg == "true") {
			DEBUG_OVERLAY_SetEnabled(true);
		} else if (arg == "off" || arg == "0" || arg == "false") {
			DEBUG_OVERLAY_SetEnabled(false);
		} else if (arg == "toggle") {
			DEBUG_OVERLAY_Toggle();
		} else {
			return "ERR usage: OVERLAY [on|off|toggle|status]\n";
		}
		int oc = 0;
		int orows = 0;
		DEBUG_OVERLAY_GetGrid(oc, orows);
		return "OK overlay=" +
		       std::string(DEBUG_OVERLAY_IsEnabled() ? "on" : "off") +
		       " grid=" + std::to_string(oc) + "x" + std::to_string(orows) +
		       "\n";
	} else if (cmd_l == "hostpause" || cmd_l == "pause") {
		// Does not need main-thread queue; request pause, reply OK.
		const std::string arg = lower_copy(rest);
		if (arg == "off" || arg == "0" || arg == "unpause" || arg == "resume") {
			GFX_RequestHostUnpause();
			return "OK hostpause=off\n";
		}
		GFX_RequestHostPause();
		return "OK hostpause=on (use HOSTUNPAUSE or Alt+Pause to resume)\n";
	} else if (cmd_l == "hostunpause" || cmd_l == "unpause" ||
	           cmd_l == "resume") {
		GFX_RequestHostUnpause();
		return "OK hostpause=off\n";
	} else if (cmd_l == "capture" || cmd_l == "shot" || cmd_l == "screenshot") {
		c.kind = CmdKind::CaptureShot;
		c.arg  = rest;
	} else if (cmd_l == "tracetoggle" || cmd_l == "debugtoggle") {
		c.kind = CmdKind::TraceToggle;
	} else if (cmd_l == "traceback" || cmd_l == "disasm" ||
	           cmd_l == "cpubacklog") {
		c.kind = CmdKind::Traceback;
		c.arg  = rest; // optional count
	} else if (cmd_l == "bp" || cmd_l == "bpint" || cmd_l == "watch" ||
	           cmd_l == "bplist" || cmd_l == "list" || cmd_l == "bpclear" ||
	           cmd_l == "clear" || cmd_l == "step" || cmd_l == "continue" ||
	           cmd_l == "cont" || cmd_l == "go" || cmd_l == "intring" ||
	           cmd_l == "snapshot" || cmd_l == "diff") {
		// Agent RE — main thread for DS/regs/mem/snapshots
		c.kind = CmdKind::AgentCmd;
		c.arg  = line; // full original line
	} else if (cmd_l == "help") {
		return "OK commands: HELLO PING STATUS KEY KEYDOWN KEYUP TYPE TEXT B800 "
		       "DUMPSCREEN DUMPMEM CAPTURE OVERLAY HOSTPAUSE HOSTUNPAUSE "
		       "TRACETOGGLE TRACEBACK [n] "
		       "BP name CS:IP | BPINT name INT [AH] | WATCH name phys:|ds: [pause|log] "
		       "LIST CLEAR STEP CONTINUE INTRING [n] [json] "
		       "SNAPSHOT tag | DIFF tagA tagB | HELP QUIT\n";
	} else if (cmd_l == "quit" || cmd_l == "exit") {
		return "OK BYE\n";
	} else {
		return "ERR unknown command (try HELP)\n";
	}

	if (cmd_l == "hello") {
		return "OK control_socket 1 (keypress emulator-mode / US layout)\n";
	}

	// TYPE can take a while; TRACEBACK can be large.
	uint32_t timeout_ms = 2000;
	if (c.kind == CmdKind::TypeText) {
		timeout_ms = static_cast<uint32_t>(
		        2000 + (g_cfg.key_hold_ms + 5) *
		                       std::max<size_t>(1, rest.size()));
	} else if (c.kind == CmdKind::Traceback || c.kind == CmdKind::AgentCmd) {
		timeout_ms = 8000;
	}
	queue_and_wait(c, timeout_ms);
	return c.reply.empty() ? "ERR empty\n" : c.reply;
}

static void client_session(const int fd)
{
	send_all(fd, "OK control_socket 1 ready\n");
	std::string line;
	while (g_running.load() && read_line(fd, line)) {
		const std::string reply = handle_line(line);
		// Ensure multi-line replies (TEXT/B800/TRACEBACK) end with newline
		if (!send_all(fd, reply)) {
			break;
		}
		if (lower_copy(line) == "quit" || lower_copy(line) == "exit") {
			break;
		}
	}
	close(fd);
}

static void accept_loop()
{
	while (g_running.load()) {
		struct pollfd pfd{};
		pfd.fd     = g_listen_fd;
		pfd.events = POLLIN;
		const int pr = poll(&pfd, 1, 250);
		if (pr < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (pr == 0) {
			continue;
		}
		const int cfd = accept(g_listen_fd, nullptr, nullptr);
		if (cfd < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			break;
		}
		// One client at a time for simplicity (serial agent)
		client_session(cfd);
	}
}

#endif // !WIN32

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void CONTROL_SOCKET_AddConfigSection(const ConfigPtr& conf)
{
	assert(conf);
	using enum Property::Changeable::Value;

	// Section names must be [a-zA-Z0-9]+ only (no underscores).
	auto* section = conf->AddSection("controlsocket");
	auto* pbool   = section->AddBool("enabled", OnlyAtStart, false);
	pbool->SetHelp(
	        "Enable UNIX-domain control socket for direct key injection and text view\n"
	        "('false' by default). Agents connect without X11/xdotool.");

	auto* pstring = section->AddString("path", OnlyAtStart,
	                                   "/tmp/dosbox-control.sock");
	pstring->SetHelp(
	        "Filesystem path of the UNIX socket ('/tmp/dosbox-control.sock' by default).");

	pstring = section->AddString("pidfile", OnlyAtStart, "");
	pstring->SetHelp(
	        "Path of the PID file written while the control socket is listening.\n"
	        "Empty or 'auto' derives it from 'path' (e.g. /tmp/dosbox-control.pid).\n"
	        "Set to 'none' to disable writing a PID file.");

	auto* pint = section->AddInt("key_hold_ms", OnlyAtStart, 30);
	pint->SetMinMax(0, 500);
	pint->SetHelp("Milliseconds to hold a KEY tap press before release (30 by default).");
}

void CONTROL_SOCKET_Init()
{
#ifdef WIN32
	(void)g_cfg;
	return;
#else
	auto* section = get_section("controlsocket");
	if (!section) {
		return;
	}
	g_cfg.enabled     = section->GetBool("enabled");
	g_cfg.path        = section->GetString("path");
	g_cfg.pidfile     = section->GetString("pidfile");
	g_cfg.key_hold_ms = section->GetInt("key_hold_ms");
	if (g_cfg.key_hold_ms < 0) {
		g_cfg.key_hold_ms = 0;
	}
	g_pidfile_written.clear();

	if (!g_cfg.enabled) {
		return;
	}

	if (g_cfg.path.empty()) {
		LOG_ERR("CONTROL_SOCKET: empty path");
		return;
	}

	const std::string pid_path = resolve_pidfile_path(g_cfg.pidfile, g_cfg.path);

	if (!clean_stale_socket(g_cfg.path, pid_path)) {
		return;
	}

	g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_listen_fd < 0) {
		LOG_ERR("CONTROL_SOCKET: socket() failed: %s", strerror(errno));
		return;
	}

	sockaddr_un addr{};
	addr.sun_family = AF_UNIX;
	if (g_cfg.path.size() >= sizeof(addr.sun_path)) {
		LOG_ERR("CONTROL_SOCKET: path too long");
		close(g_listen_fd);
		g_listen_fd = -1;
		return;
	}
	std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_cfg.path.c_str());

	if (bind(g_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) <
	    0) {
		LOG_ERR("CONTROL_SOCKET: bind(%s) failed: %s",
		        g_cfg.path.c_str(),
		        strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return;
	}
	if (listen(g_listen_fd, 2) < 0) {
		LOG_ERR("CONTROL_SOCKET: listen failed: %s", strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		unlink(g_cfg.path.c_str());
		return;
	}

	// Non-blocking accept via poll
	const int fl = fcntl(g_listen_fd, F_GETFL, 0);
	if (fl >= 0) {
		fcntl(g_listen_fd, F_SETFL, fl | O_NONBLOCK);
	}

	if (!pid_path.empty()) {
		if (write_pidfile(pid_path)) {
			g_pidfile_written = pid_path;
		}
	}

	g_running.store(true);
	g_accept_thread = std::thread(accept_loop);
	LOG_MSG("CONTROL_SOCKET: listening on %s (pid=%d%s%s)",
	        g_cfg.path.c_str(),
	        static_cast<int>(getpid()),
	        g_pidfile_written.empty() ? "" : ", pidfile=",
	        g_pidfile_written.empty() ? "" : g_pidfile_written.c_str());
#endif
}

void CONTROL_SOCKET_Shutdown()
{
#ifdef WIN32
	return;
#else
	g_running.store(false);
	if (g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}
	if (g_accept_thread.joinable()) {
		g_accept_thread.join();
	}
	if (!g_cfg.path.empty()) {
		unlink(g_cfg.path.c_str());
	}
	if (!g_pidfile_written.empty()) {
		unlink(g_pidfile_written.c_str());
		g_pidfile_written.clear();
	}
	// drain queue
	std::lock_guard<std::mutex> lock(g_mtx);
	for (auto* c : g_queue) {
		c->reply = "ERR shutdown\n";
		c->done  = true;
	}
	g_queue.clear();
	g_cv.notify_all();
#endif
}

void CONTROL_SOCKET_Poll()
{
#ifdef WIN32
	return;
#else
	if (!g_running.load()) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_mtx);
	if (g_queue.empty()) {
		return;
	}
	for (auto* cmd : g_queue) {
		execute_on_main(*cmd);
		cmd->done = true;
	}
	g_queue.clear();
	g_cv.notify_all();
#endif
}
