// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#include "cpu_backlog.h"
#include "insn_length.h"

#include "cpu/lazyflags.h"
#include "cpu/registers.h"
#include "hardware/memory.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

struct Entry {
	uint16_t cs = 0;
	uint16_t ip = 0;
	uint8_t len = 0;
	uint8_t bytes[15]{};

	// Populated per regs mode (unused fields left 0)
	uint16_t ax = 0;
	uint16_t bx = 0;
	uint16_t cx = 0;
	uint16_t dx = 0;
	uint16_t si = 0;
	uint16_t di = 0;
	uint16_t bp = 0;
	uint16_t sp = 0;
	uint16_t ds = 0;
	uint16_t es = 0;
	uint16_t ss = 0;
	uint16_t flags = 0;
};

CpuBacklogConfig g_cfg{};
std::vector<Entry> g_ring;
size_t g_head  = 0; // next write index
size_t g_count = 0; // entries filled (≤ capacity)
std::mutex g_mtx;
bool g_ready = false;

void capture_regs(Entry& e)
{
	if (g_cfg.regs == CpuBacklogRegs::None) {
		return;
	}

	FillFlags();
	e.ax    = reg_ax;
	e.dx    = reg_dx;
	e.ds    = SegValue(ds);
	e.flags = static_cast<uint16_t>(reg_flags & 0xFFFF);

	if (g_cfg.regs == CpuBacklogRegs::Full) {
		e.bx = reg_bx;
		e.cx = reg_cx;
		e.si = reg_si;
		e.di = reg_di;
		e.bp = reg_bp;
		e.sp = reg_sp;
		e.es = SegValue(es);
		e.ss = SegValue(ss);
	}
}

void append_now_regs(std::string& out)
{
	FillFlags();
	char line[256];
	std::snprintf(line,
	              sizeof(line),
	              "NOW AX=%04X BX=%04X CX=%04X DX=%04X SI=%04X DI=%04X "
	              "BP=%04X SP=%04X DS=%04X ES=%04X SS=%04X CS=%04X IP=%04X "
	              "FLAGS=%04X\n",
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
	out += line;
}

void format_entry(std::string& out, size_t idx, const Entry& e)
{
	char head[96];
	std::snprintf(head,
	              sizeof(head),
	              "%04zu CS=%04X IP=%04X BYTES=",
	              idx,
	              e.cs,
	              e.ip);
	out += head;
	for (uint8_t i = 0; i < e.len; ++i) {
		char b[4];
		std::snprintf(b, sizeof(b), "%02X", e.bytes[i]);
		out += b;
		if (i + 1 < e.len) {
			out += ' ';
		}
	}

	if (g_cfg.regs == CpuBacklogRegs::Minimal) {
		char r[80];
		std::snprintf(r,
		              sizeof(r),
		              " AX=%04X DX=%04X DS=%04X FLAGS=%04X",
		              e.ax,
		              e.dx,
		              e.ds,
		              e.flags);
		out += r;
	} else if (g_cfg.regs == CpuBacklogRegs::Full) {
		char r[160];
		std::snprintf(r,
		              sizeof(r),
		              " AX=%04X BX=%04X CX=%04X DX=%04X SI=%04X DI=%04X "
		              "BP=%04X SP=%04X DS=%04X ES=%04X SS=%04X FLAGS=%04X",
		              e.ax,
		              e.bx,
		              e.cx,
		              e.dx,
		              e.si,
		              e.di,
		              e.bp,
		              e.sp,
		              e.ds,
		              e.es,
		              e.ss,
		              e.flags);
		out += r;
	}
	out += '\n';
}

} // namespace

CpuBacklogRegs CpuBacklog_ParseRegsMode(const std::string& s_in)
{
	std::string s = s_in;
	for (auto& c : s) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	if (s == "full" || s == "all") {
		return CpuBacklogRegs::Full;
	}
	if (s == "none" || s == "off" || s == "0" || s == "false") {
		return CpuBacklogRegs::None;
	}
	return CpuBacklogRegs::Minimal;
}

void CpuBacklog_Init(const CpuBacklogConfig& cfg)
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_cfg = cfg;
	if (g_cfg.max_insns < 16) {
		g_cfg.max_insns = 16;
	}
	if (g_cfg.max_insns > 65536) {
		g_cfg.max_insns = 65536;
	}
	g_ring.assign(static_cast<size_t>(g_cfg.max_insns), Entry{});
	g_head  = 0;
	g_count = 0;
	g_ready = g_cfg.enabled;
}

void CpuBacklog_Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_ready = false;
	g_ring.clear();
	g_head  = 0;
	g_count = 0;
}

void CpuBacklog_Clear()
{
	std::lock_guard<std::mutex> lock(g_mtx);
	g_head  = 0;
	g_count = 0;
}

bool CpuBacklog_IsEnabled()
{
	return g_ready;
}

void CpuBacklog_Push(const uint16_t cs_val, const uint16_t ip_val)
{
	if (!g_ready) {
		return;
	}

	const uint32_t phys_base = (static_cast<uint32_t>(cs_val) << 4) & 0xFFFFF;
	const uint32_t phys_ip   = (phys_base + static_cast<uint32_t>(ip_val)) &
	                         0xFFFFF;
	int len = x86_insn_length_real_mode(phys_ip);
	if (len < 1) {
		len = 1;
	}
	if (len > 15) {
		len = 15;
	}

	Entry e{};
	e.cs  = cs_val;
	e.ip  = ip_val;
	e.len = static_cast<uint8_t>(len);
	for (int i = 0; i < len; ++i) {
		e.bytes[i] = mem_readb((phys_ip + static_cast<uint32_t>(i)) &
		                       0xFFFFF);
	}
	capture_regs(e);

	std::lock_guard<std::mutex> lock(g_mtx);
	if (g_ring.empty()) {
		return;
	}
	g_ring[g_head] = e;
	g_head         = (g_head + 1) % g_ring.size();
	if (g_count < g_ring.size()) {
		++g_count;
	}
}

std::string CpuBacklog_FormatTraceback(int count)
{
	std::lock_guard<std::mutex> lock(g_mtx);

	const char* reg_name = "minimal";
	if (g_cfg.regs == CpuBacklogRegs::None) {
		reg_name = "none";
	} else if (g_cfg.regs == CpuBacklogRegs::Full) {
		reg_name = "full";
	}

	if (!g_ready || g_count == 0) {
		std::string out = "OK TRACEBACK n=0 cap=";
		out += std::to_string(g_cfg.max_insns);
		out += " regs=";
		out += reg_name;
		out += " enabled=";
		out += g_ready ? "true" : "false";
		out += "\n";
		// Still emit NOW regs for RE even if ring empty
		append_now_regs(out);
		out += "END\n";
		return out;
	}

	int n = count;
	if (n <= 0 || static_cast<size_t>(n) > g_count) {
		n = static_cast<int>(g_count);
	}

	std::string out;
	out.reserve(static_cast<size_t>(n) * 96 + 256);
	out += "OK TRACEBACK n=";
	out += std::to_string(n);
	out += " cap=";
	out += std::to_string(g_cfg.max_insns);
	out += " regs=";
	out += reg_name;
	out += "\n";

	append_now_regs(out);

	// Oldest of the last n … newest
	// head points to next write = one past newest
	const size_t cap = g_ring.size();
	for (int i = 0; i < n; ++i) {
		// i=0 → oldest among last n
		const size_t idx =
		        (g_head + cap - static_cast<size_t>(n - i)) % cap;
		format_entry(out, static_cast<size_t>(i), g_ring[idx]);
	}
	out += "END\n";
	return out;
}
