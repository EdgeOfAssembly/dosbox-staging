// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#include "agent_re.h"
#include "cpu_backlog.h"
#include "game_trace.h"
#include "mem_dump.h"
#include "screen_dump.h"

#include "capture/capture.h"
#include "cpu/lazyflags.h"
#include "cpu/registers.h"
#include "gui/common.h"
#include "hardware/memory.h"
#include "misc/logging.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

struct Breakpoint {
	std::string name;
	uint16_t cs = 0;
	uint16_t ip = 0;
	bool enabled = true;
};

struct IntBreakpoint {
	std::string name;
	uint8_t int_num = 0;
	int ah = -1; // -1 = any
	bool enabled = true;
};

struct Watch {
	std::string name;
	uint32_t phys_lo = 0;
	uint32_t phys_hi = 0; // inclusive
	bool enabled = true;
	bool hit_pause = true;
};

struct IntRingEntry {
	uint8_t int_num = 0;
	uint16_t ax = 0;
	uint16_t cs = 0;
	uint16_t ip = 0;
	uint16_t ds = 0;
};

constexpr size_t kIntRingCap = 64;

std::mutex g_mtx;
std::vector<Breakpoint> g_bps;
std::vector<IntBreakpoint> g_int_bps;
std::vector<Watch> g_watches;
std::vector<IntRingEntry> g_int_ring;
size_t g_int_head  = 0;
size_t g_int_count = 0;

bool g_ready           = false;
bool g_step_armed      = false; // trap after next insn once running
bool g_step_pending    = false; // will trap on next OnInstruction
std::string g_last_trap;
std::string g_snap_dir = "re_snaps";

// Hot-path flags (written only under lock or from main thread after lock)
bool g_need_insn = false;
bool g_need_mem  = false;

void refresh_hot_flags_unlocked()
{
	g_need_mem = false;
	for (const auto& w : g_watches) {
		if (w.enabled) {
			g_need_mem = true;
			break;
		}
	}
	g_need_insn = g_step_armed || g_step_pending;
	if (!g_need_insn) {
		for (const auto& b : g_bps) {
			if (b.enabled) {
				g_need_insn = true;
				break;
			}
		}
	}
}

void trap(const std::string& reason)
{
	g_last_trap = reason;
	LOG_MSG("AGENT_RE: TRAP %s", reason.c_str());
	// Soft-freeze CPU backlog by requesting host pause (stops g_trace_enabled)
	GFX_RequestHostPause();
}

std::string lower(std::string s)
{
	for (auto& c : s) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return s;
}

std::vector<std::string> split_ws(const std::string& s)
{
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) {
		if (c == ' ' || c == '\t') {
			if (!cur.empty()) {
				out.push_back(cur);
				cur.clear();
			}
		} else {
			cur.push_back(c);
		}
	}
	if (!cur.empty()) {
		out.push_back(cur);
	}
	return out;
}

bool parse_u16(const std::string& s, uint16_t& v)
{
	try {
		size_t idx = 0;
		unsigned long x = std::stoul(s, &idx, 0);
		if (idx != s.size() || x > 0xFFFF) {
			return false;
		}
		v = static_cast<uint16_t>(x);
		return true;
	} catch (...) {
		return false;
	}
}

bool parse_hex_u16(const std::string& s, uint16_t& v)
{
	// Always hex — CS:IP tokens are routinely written as 01AD:4B4F.
	// Base-0 stoul treats leading 0 as octal and rejects 01ad after lower().
	try {
		size_t idx = 0;
		std::string t = s;
		if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
			t = t.substr(2);
		}
		unsigned long x = std::stoul(t, &idx, 16);
		if (idx != t.size() || x > 0xFFFF) {
			return false;
		}
		v = static_cast<uint16_t>(x);
		return true;
	} catch (...) {
		return false;
	}
}

bool parse_csip(const std::string& s, uint16_t& cs, uint16_t& ip)
{
	const auto pos = s.find(':');
	if (pos == std::string::npos) {
		return false;
	}
	return parse_hex_u16(s.substr(0, pos), cs) &&
	       parse_hex_u16(s.substr(pos + 1), ip);
}

// phys:HEX or ds:OFF or ds:OFF+SIZE
bool parse_watch_range(const std::string& s, uint32_t& lo, uint32_t& hi,
                       std::string& err)
{
	const auto low = lower(s);
	if (low.rfind("phys:", 0) == 0) {
		std::string rest = s.substr(5);
		const auto plus  = rest.find('+');
		uint32_t base    = 0;
		uint32_t size    = 1;
		try {
			if (plus == std::string::npos) {
				base = std::stoul(rest, nullptr, 16);
			} else {
				base = std::stoul(rest.substr(0, plus), nullptr, 16);
				size = std::stoul(rest.substr(plus + 1), nullptr, 16);
			}
		} catch (...) {
			err = "bad phys range";
			return false;
		}
		if (size == 0) {
			size = 1;
		}
		lo = base & 0xFFFFF;
		hi = (base + size - 1) & 0xFFFFF;
		return true;
	}
	if (low.rfind("ds:", 0) == 0) {
		std::string rest = s.substr(3);
		const auto plus  = rest.find('+');
		uint32_t off     = 0;
		uint32_t size    = 1;
		try {
			if (plus == std::string::npos) {
				off = std::stoul(rest, nullptr, 16);
			} else {
				off  = std::stoul(rest.substr(0, plus), nullptr, 16);
				size = std::stoul(rest.substr(plus + 1), nullptr, 16);
			}
		} catch (...) {
			err = "bad ds range";
			return false;
		}
		if (size == 0) {
			size = 1;
		}
		const uint32_t base = (static_cast<uint32_t>(SegValue(ds)) << 4) +
		                      off;
		lo = base & 0xFFFFF;
		hi = (base + size - 1) & 0xFFFFF;
		return true;
	}
	err = "use phys:HEX[+SIZE] or ds:OFF[+SIZE]";
	return false;
}

void push_int_ring(uint8_t int_num)
{
	IntRingEntry e{};
	e.int_num = int_num;
	e.ax      = reg_ax;
	e.cs      = SegValue(cs);
	e.ip      = static_cast<uint16_t>(reg_eip);
	e.ds      = SegValue(ds);
	if (g_int_ring.empty()) {
		g_int_ring.resize(kIntRingCap);
	}
	g_int_ring[g_int_head] = e;
	g_int_head             = (g_int_head + 1) % kIntRingCap;
	if (g_int_count < kIntRingCap) {
		++g_int_count;
	}
}

std::string now_regs_line()
{
	FillFlags();
	char line[256];
	std::snprintf(line,
	              sizeof(line),
	              "AX=%04X BX=%04X CX=%04X DX=%04X SI=%04X DI=%04X "
	              "BP=%04X SP=%04X DS=%04X ES=%04X SS=%04X CS=%04X IP=%04X "
	              "FLAGS=%04X",
	              reg_ax,
	              reg_bx,
	              reg_cx,
	              reg_dx,
	              reg_si,
	              reg_di,
	              reg_bp,
	              reg_sp,
	              SegValue(ds),
	              SegValue(es),
	              SegValue(ss),
	              SegValue(cs),
	              static_cast<uint16_t>(reg_eip),
	              static_cast<uint16_t>(reg_flags & 0xFFFF));
	return line;
}

bool write_text(const std::string& path, const std::string& s)
{
	// mkdir -p style for re_snaps/tag
	std::string dir = path;
	const auto slash = dir.find_last_of('/');
	if (slash != std::string::npos) {
		dir.resize(slash);
		std::string cur;
		for (size_t i = 0; i < dir.size(); ++i) {
			cur.push_back(dir[i]);
			if (dir[i] == '/' || i + 1 == dir.size()) {
				if (cur.size() > 0 && cur != "." && cur != "/") {
					::mkdir(cur.c_str(), 0755);
				}
			}
		}
		// also final without trailing issues
		::mkdir(dir.c_str(), 0755);
	}
	std::ofstream f(path);
	if (!f) {
		return false;
	}
	f << s;
	return true;
}

std::string b800_hex()
{
	// 40x25 or 80x25 text page
	const uint8_t mode = ScreenDump_CurrentMode();
	uint32_t base      = 0xB8000;
	uint32_t size      = 80 * 25 * 2;
	if (mode == 0x00 || mode == 0x01) {
		size = 40 * 25 * 2;
	} else if (mode == 0x07) {
		base = 0xB0000;
	}
	std::string out;
	out.reserve(size * 2 + 32);
	char tmp[8];
	std::snprintf(tmp, sizeof(tmp), "mode=%02X\n", mode);
	out += tmp;
	static const char* hexd = "0123456789abcdef";
	for (uint32_t i = 0; i < size; ++i) {
		const uint8_t b = mem_readb(base + i);
		out.push_back(hexd[b >> 4]);
		out.push_back(hexd[b & 0xf]);
	}
	out.push_back('\n');
	return out;
}

} // namespace

bool AgentRe_NeedsInsnHook()
{
	return g_ready && g_need_insn;
}

bool AgentRe_NeedsMemWatch()
{
	return g_ready && g_need_mem;
}

void AgentRe_OnInstruction(const uint16_t cs_val, const uint16_t ip_val)
{
	if (!g_ready) {
		return;
	}

	if (g_step_pending) {
		g_step_pending = false;
		g_step_armed   = false;
		refresh_hot_flags_unlocked();
		char reason[64];
		std::snprintf(reason,
		              sizeof(reason),
		              "STEP at %04X:%04X",
		              cs_val,
		              ip_val);
		trap(reason);
		return;
	}

	if (g_step_armed) {
		// First insn after CONTINUE with step: arm trap for *next* insn
		g_step_armed   = false;
		g_step_pending = true;
		refresh_hot_flags_unlocked();
		return;
	}

	std::string reason;
	{
		std::lock_guard<std::mutex> lock(g_mtx);
		for (const auto& b : g_bps) {
			if (b.enabled && b.cs == cs_val && b.ip == ip_val) {
				char buf[96];
				std::snprintf(buf,
				              sizeof(buf),
				              "BP %s at %04X:%04X",
				              b.name.c_str(),
				              cs_val,
				              ip_val);
				reason = buf;
				break;
			}
		}
	}
	if (!reason.empty()) {
		trap(reason);
	}
}

void AgentRe_OnMemWrite(const uint32_t phys, const uint8_t old_val,
                        const uint8_t new_val)
{
	if (!g_ready || !g_need_mem || old_val == new_val) {
		return;
	}
	const uint32_t p = phys & 0xFFFFF;

	std::string reason;
	{
		std::lock_guard<std::mutex> lock(g_mtx);
		for (const auto& w : g_watches) {
			if (!w.enabled) {
				continue;
			}
			if (p >= w.phys_lo && p <= w.phys_hi) {
				char buf[128];
				std::snprintf(buf,
				              sizeof(buf),
				              "WATCH %s phys=%05X old=%02X new=%02X "
				              "CS:IP=%04X:%04X",
				              w.name.c_str(),
				              p,
				              old_val,
				              new_val,
				              SegValue(cs),
				              static_cast<uint16_t>(reg_eip));
				reason = buf;
				if (w.hit_pause) {
					break;
				}
				// log-only: keep scanning
				LOG_MSG("AGENT_RE: %s", buf);
				reason.clear();
			}
		}
	}
	if (!reason.empty()) {
		trap(reason);
	}
}

void AgentRe_OnInterrupt(const uint8_t int_num)
{
	if (!g_ready) {
		return;
	}

	std::string reason;
	{
		std::lock_guard<std::mutex> lock(g_mtx);
		push_int_ring(int_num);
		const uint8_t ah = static_cast<uint8_t>((reg_ax >> 8) & 0xFF);
		for (const auto& b : g_int_bps) {
			if (!b.enabled || b.int_num != int_num) {
				continue;
			}
			if (b.ah >= 0 && b.ah != static_cast<int>(ah)) {
				continue;
			}
			char buf[96];
			std::snprintf(buf,
			              sizeof(buf),
			              "BPINT %s INT %02X AH=%02X CS:IP=%04X:%04X",
			              b.name.c_str(),
			              int_num,
			              ah,
			              SegValue(cs),
			              static_cast<uint16_t>(reg_eip));
			reason = buf;
			break;
		}
	}
	if (!reason.empty()) {
		trap(reason);
	}
}

void AgentRe_Init(const std::string& snap_dir)
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_snap_dir = snap_dir.empty() ? "re_snaps" : snap_dir;
	g_ready    = true;
	g_bps.clear();
	g_int_bps.clear();
	g_watches.clear();
	g_int_ring.assign(kIntRingCap, IntRingEntry{});
	g_int_head     = 0;
	g_int_count    = 0;
	g_step_armed   = false;
	g_step_pending = false;
	g_last_trap.clear();
	refresh_hot_flags_unlocked();
	LOG_MSG("AGENT_RE: ready (snap_dir=%s)", g_snap_dir.c_str());
}

void AgentRe_Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_ready = false;
	g_bps.clear();
	g_int_bps.clear();
	g_watches.clear();
	g_need_insn = false;
	g_need_mem  = false;
}

void AgentRe_ClearAll()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_bps.clear();
	g_int_bps.clear();
	g_watches.clear();
	g_step_armed   = false;
	g_step_pending = false;
	g_last_trap.clear();
	refresh_hot_flags_unlocked();
}

void AgentRe_RequestStep()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_step_armed   = true;
	g_step_pending = false;
	refresh_hot_flags_unlocked();
	GFX_RequestHostUnpause();
}

void AgentRe_RequestContinue()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_step_armed   = false;
	g_step_pending = false;
	refresh_hot_flags_unlocked();
	GFX_RequestHostUnpause();
}

std::string AgentRe_LastTrapReason()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	return g_last_trap.empty() ? std::string("(none)") : g_last_trap;
}

std::string AgentRe_IntRingFormat(int count, const bool json)
{
	std::lock_guard<std::mutex> lock(g_mtx);
	if (g_int_count == 0) {
		return json ? "[]\n" : "OK INTRING n=0\nEND\n";
	}
	int n = count;
	if (n <= 0 || static_cast<size_t>(n) > g_int_count) {
		n = static_cast<int>(g_int_count);
	}
	std::string out;
	if (json) {
		out = "[\n";
		for (int i = 0; i < n; ++i) {
			const size_t idx =
			        (g_int_head + kIntRingCap - static_cast<size_t>(n - i)) %
			        kIntRingCap;
			const auto& e = g_int_ring[idx];
			char line[160];
			std::snprintf(line,
			              sizeof(line),
			              "  {\"i\":%d,\"int\":%u,\"ah\":%u,\"al\":%u,"
			              "\"ax\":\"%04X\",\"cs\":\"%04X\",\"ip\":\"%04X\","
			              "\"ds\":\"%04X\"}%s\n",
			              i,
			              e.int_num,
			              (e.ax >> 8) & 0xFF,
			              e.ax & 0xFF,
			              e.ax,
			              e.cs,
			              e.ip,
			              e.ds,
			              (i + 1 < n) ? "," : "");
			out += line;
		}
		out += "]\n";
		return out;
	}
	out = "OK INTRING n=" + std::to_string(n) + "\n";
	for (int i = 0; i < n; ++i) {
		const size_t idx =
		        (g_int_head + kIntRingCap - static_cast<size_t>(n - i)) %
		        kIntRingCap;
		const auto& e = g_int_ring[idx];
		char line[128];
		std::snprintf(line,
		              sizeof(line),
		              "%04d INT %02X AX=%04X CS=%04X IP=%04X DS=%04X\n",
		              i,
		              e.int_num,
		              e.ax,
		              e.cs,
		              e.ip,
		              e.ds);
		out += line;
	}
	out += "END\n";
	return out;
}

std::string AgentRe_Snapshot(const std::string& tag_in)
{
	std::string tag = tag_in.empty() ? "snap" : tag_in;
	for (char& c : tag) {
		if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' &&
		    c != '-') {
			c = '_';
		}
	}

	const std::string dir = g_snap_dir + "/" + tag;

	// Force host pause so state is stable
	GFX_RequestHostPause();

	const std::string regs = now_regs_line();
	write_text(dir + "/now_regs.txt", regs + "\n");
	write_text(dir + "/trap.txt", AgentRe_LastTrapReason() + "\n");

	const std::string tb = CpuBacklog_FormatTraceback(0);
	write_text(dir + "/traceback.txt", tb);
	write_text(dir + "/traceback_raw.txt", tb);

	const std::string ir = AgentRe_IntRingFormat(0, false);
	write_text(dir + "/int_ring.txt", ir);
	write_text(dir + "/int_ring.json", AgentRe_IntRingFormat(0, true));

	write_text(dir + "/b800.hex", b800_hex());

	ScreenDump_Hotkey(true);
	ScreenDump_Hotkey(false);
	MemDump_Hotkey(true);
	MemDump_Hotkey(false);
	CAPTURE_RequestRenderedScreenshot();

	std::ostringstream idx;
	idx << "{\n"
	    << "  \"tag\": \"" << tag << "\",\n"
	    << "  \"dir\": \"" << dir << "\",\n"
	    << "  \"trap\": \"" << AgentRe_LastTrapReason() << "\",\n"
	    << "  \"regs\": \"" << regs << "\",\n"
	    << "  \"files\": [\"now_regs.txt\",\"traceback.txt\",\"int_ring.txt\","
	       "\"int_ring.json\",\"b800.hex\",\"trap.txt\"]\n"
	    << "}\n";
	write_text(dir + "/index.json", idx.str());

	std::string reply = "OK SNAPSHOT tag=" + tag + " dir=" + dir + "\n";
	reply += "trap=" + AgentRe_LastTrapReason() + "\n";
	reply += regs + "\n";
	reply += "END\n";
	return reply;
}

static std::string load_file(const std::string& path)
{
	std::ifstream f(path);
	if (!f) {
		return {};
	}
	return std::string((std::istreambuf_iterator<char>(f)),
	                   std::istreambuf_iterator<char>());
}

std::string AgentRe_Diff(const std::string& tag_a, const std::string& tag_b)
{
	const std::string da = g_snap_dir + "/" + tag_a;
	const std::string db = g_snap_dir + "/" + tag_b;
	std::string out      = "OK DIFF a=" + tag_a + " b=" + tag_b + "\n";

	const std::string ra = load_file(da + "/now_regs.txt");
	const std::string rb = load_file(db + "/now_regs.txt");
	if (ra != rb) {
		out += "regs_changed:\n  a: " + ra + "  b: " + rb;
	} else {
		out += "regs: identical\n";
	}

	const std::string ba = load_file(da + "/b800.hex");
	const std::string bb = load_file(db + "/b800.hex");
	if (ba.empty() || bb.empty()) {
		out += "b800: missing file(s)\n";
	} else if (ba == bb) {
		out += "b800: identical\n";
	} else {
		auto hexbody = [](const std::string& s) {
			const auto pos = s.find('\n');
			return pos == std::string::npos ? s : s.substr(pos + 1);
		};
		const std::string ha = hexbody(ba);
		const std::string hb = hexbody(bb);
		size_t diffs         = 0;
		const size_t n       = std::min(ha.size(), hb.size());
		for (size_t i = 0; i + 1 < n; i += 2) {
			if (ha[i] != hb[i] || ha[i + 1] != hb[i + 1]) {
				++diffs;
			}
		}
		out += "b800: " + std::to_string(diffs) + " byte(s) differ\n";
	}
	out += "END\n";
	return out;
}

std::string AgentRe_Cmd(const std::string& line)
{
	if (!g_ready) {
		return "ERR agent_re not ready (debugtrace enabled?)\n";
	}

	auto toks = split_ws(line);
	if (toks.empty()) {
		return "ERR empty\n";
	}
	const std::string cmd = lower(toks[0]);

	auto need = [&](size_t n) -> bool { return toks.size() >= n; };

	if (cmd == "bp" || cmd == "break") {
		// BP name CS:IP
		if (!need(3)) {
			return "ERR usage: BP <name> <CS:IP>\n";
		}
		uint16_t cs = 0;
		uint16_t ip = 0;
		if (!parse_csip(toks[2], cs, ip)) {
			return "ERR bad CS:IP\n";
		}
		std::lock_guard<std::mutex> lock(g_mtx);
		Breakpoint b;
		b.name = toks[1];
		b.cs   = cs;
		b.ip   = ip;
		g_bps.push_back(b);
		refresh_hot_flags_unlocked();
		char buf[80];
		std::snprintf(buf, sizeof(buf), "OK BP %s %04X:%04X\n", b.name.c_str(), cs, ip);
		return buf;
	}
	if (cmd == "bpint") {
		// BPINT name INT [AH]
		if (!need(3)) {
			return "ERR usage: BPINT <name> <INT> [AH]\n";
		}
		uint16_t inum = 0;
		if (!parse_u16(toks[2], inum) || inum > 255) {
			return "ERR bad INT\n";
		}
		IntBreakpoint b;
		b.name    = toks[1];
		b.int_num = static_cast<uint8_t>(inum);
		if (toks.size() >= 4) {
			uint16_t ah = 0;
			if (!parse_u16(toks[3], ah) || ah > 255) {
				return "ERR bad AH\n";
			}
			b.ah = static_cast<int>(ah);
		}
		std::lock_guard<std::mutex> lock(g_mtx);
		g_int_bps.push_back(b);
		char buf[80];
		std::snprintf(buf,
		              sizeof(buf),
		              "OK BPINT %s INT %02X AH=%s\n",
		              b.name.c_str(),
		              b.int_num,
		              b.ah < 0 ? "*" : std::to_string(b.ah).c_str());
		return buf;
	}
	if (cmd == "watch") {
		// WATCH name phys:..|ds:.. [pause|log]
		if (!need(3)) {
			return "ERR usage: WATCH <name> <phys:HEX[+SZ]|ds:OFF[+SZ]> [pause|log]\n";
		}
		uint32_t lo = 0;
		uint32_t hi = 0;
		std::string err;
		if (!parse_watch_range(toks[2], lo, hi, err)) {
			return "ERR " + err + "\n";
		}
		Watch w;
		w.name      = toks[1];
		w.phys_lo   = lo;
		w.phys_hi   = hi;
		w.hit_pause = true;
		if (toks.size() >= 4 && lower(toks[3]) == "log") {
			w.hit_pause = false;
		}
		std::lock_guard<std::mutex> lock(g_mtx);
		g_watches.push_back(w);
		refresh_hot_flags_unlocked();
		char buf[96];
		std::snprintf(buf,
		              sizeof(buf),
		              "OK WATCH %s %05X-%05X pause=%s\n",
		              w.name.c_str(),
		              lo,
		              hi,
		              w.hit_pause ? "true" : "false");
		return buf;
	}
	if (cmd == "bplist" || cmd == "watches" || cmd == "list") {
		std::lock_guard<std::mutex> lock(g_mtx);
		std::string out = "OK LIST\n";
		for (const auto& b : g_bps) {
			char line[80];
			std::snprintf(line,
			              sizeof(line),
			              "BP %s %04X:%04X en=%d\n",
			              b.name.c_str(),
			              b.cs,
			              b.ip,
			              b.enabled ? 1 : 0);
			out += line;
		}
		for (const auto& b : g_int_bps) {
			char line[80];
			std::snprintf(line,
			              sizeof(line),
			              "BPINT %s INT %02X AH=%s en=%d\n",
			              b.name.c_str(),
			              b.int_num,
			              b.ah < 0 ? "*" : std::to_string(b.ah).c_str(),
			              b.enabled ? 1 : 0);
			out += line;
		}
		for (const auto& w : g_watches) {
			char line[96];
			std::snprintf(line,
			              sizeof(line),
			              "WATCH %s %05X-%05X pause=%d en=%d\n",
			              w.name.c_str(),
			              w.phys_lo,
			              w.phys_hi,
			              w.hit_pause ? 1 : 0,
			              w.enabled ? 1 : 0);
			out += line;
		}
		out += "trap=" + (g_last_trap.empty() ? std::string("(none)")
		                                      : g_last_trap) +
		       "\nEND\n";
		return out;
	}
	if (cmd == "bpclear" || cmd == "clear") {
		AgentRe_ClearAll();
		return "OK cleared BP/WATCH/step\n";
	}
	if (cmd == "step") {
		AgentRe_RequestStep();
		return "OK STEP (will trap after next insn)\n";
	}
	if (cmd == "continue" || cmd == "cont" || cmd == "go") {
		AgentRe_RequestContinue();
		return "OK CONTINUE\n";
	}
	if (cmd == "intring") {
		int n = 0;
		if (toks.size() >= 2) {
			try {
				n = std::stoi(toks[1]);
			} catch (...) {
				n = 0;
			}
		}
		const bool json = (toks.size() >= 3 && lower(toks[2]) == "json") ||
		                  (toks.size() >= 2 && lower(toks[1]) == "json");
		return AgentRe_IntRingFormat(json ? 0 : n, json);
	}

	return "ERR unknown agent cmd (BP BPINT WATCH LIST CLEAR STEP CONTINUE INTRING)\n";
}
