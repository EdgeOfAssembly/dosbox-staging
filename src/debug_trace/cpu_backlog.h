// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_CPU_BACKLOG_H
#define DOSBOX_CPU_BACKLOG_H

#include <cstdint>
#include <string>

// Rolling ring of recently executed real-mode instructions for RE.
// Filled from the normal-core instruction hook while g_trace_enabled.
// Freezes automatically when host-paused (hook stops). Does not write VRAM.

enum class CpuBacklogRegs : uint8_t {
	None    = 0,
	Minimal = 1, // AX DX DS FLAGS
	Full    = 2, // all GP + segs + FLAGS
};

struct CpuBacklogConfig {
	bool enabled       = false;
	int max_insns      = 512; // ring capacity
	CpuBacklogRegs regs = CpuBacklogRegs::Minimal;
};

void CpuBacklog_Init(const CpuBacklogConfig& cfg);
void CpuBacklog_Shutdown();
void CpuBacklog_Clear();

bool CpuBacklog_IsEnabled();

// Push one executed instruction at CS:IP (before it runs). Cheap when enabled.
void CpuBacklog_Push(uint16_t cs_val, uint16_t ip_val);

// Format last `count` entries (0 = all in ring). Includes NOW register block.
// Safe to call from control-socket thread if ring is only written on main thread
// and we snapshot under a mutex — Push is main-thread only; Format takes lock.
std::string CpuBacklog_FormatTraceback(int count);

// Parse "none" / "minimal" / "full"
CpuBacklogRegs CpuBacklog_ParseRegsMode(const std::string& s);

#endif
