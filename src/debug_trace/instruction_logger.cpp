// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Per-instruction disassembly + register-dump logger.
//
// Rather than embedding a full disassembler we fetch the raw opcode bytes and
// print them as a hex sequence alongside the full 16-bit register state.  This
// keeps the implementation self-contained while still giving reverse engineers
// the information they need to correlate with a proper disassembler.

#include "instruction_logger.h"
#include "game_trace.h"

#include "cpu/registers.h"
#include "cpu/lazyflags.h"
#include "hardware/memory.h"

#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
// Sample-rate counter (file-local)
// ---------------------------------------------------------------------------
static int s_sample_counter = 0;

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void InstructionLogger_Log(const uint16_t cs_val, const uint16_t ip_val)
{
	const int sample_rate = DEBUGTRACE_InstructionSampleRate();
	if (sample_rate > 1) {
		++s_sample_counter;
		if (s_sample_counter < sample_rate) {
			return;
		}
		s_sample_counter = 0;
	}

	// Materialise CPU flags into reg_flags
	FillFlags();

	// Read up to 8 opcode bytes for display.
	// Apply 20-bit real-mode address wrapping so addresses above 0xFFFFF
	// wrap correctly (e.g. CS:IP = FFFF:FFF8 must not read past 1 MB).
	// This logs the bytes ABOUT TO BE executed (before decode/execute).
	const uint32_t phys_base = (static_cast<uint32_t>(cs_val) << 4) & 0xFFFFF;
	const uint32_t phys_ip   = (phys_base + static_cast<uint32_t>(ip_val)) & 0xFFFFF;
	char opcode_hex[8 * 3 + 1]; // "XX XX XX ..." + NUL
	char* wp = opcode_hex;
	for (int i = 0; i < 8; ++i) {
		const uint32_t addr  = (phys_ip + static_cast<uint32_t>(i)) & 0xFFFFF;
		const uint8_t  byte  = mem_readb(addr);
		wp += snprintf(wp, 4, "%02X ", byte);
	}
	// Trim trailing space
	if (wp > opcode_hex) {
		*(wp - 1) = '\0';
	}

	char line[512];
	const int written = snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] CS:IP=%04X:%04X  BYTES=%-23s  "
	         "AX=%04X BX=%04X CX=%04X DX=%04X "
	         "SI=%04X DI=%04X BP=%04X SP=%04X "
	         "DS=%04X ES=%04X SS=%04X FL=%04X",
	         DEBUGTRACE_GetElapsedMs(),
	         cs_val, ip_val,
	         opcode_hex,
	         reg_ax, reg_bx, reg_cx, reg_dx,
	         reg_si, reg_di, reg_bp, reg_sp,
	         SegValue(ds), SegValue(es), SegValue(ss),
	         static_cast<uint16_t>(reg_flags & 0xFFFF));
	assert(written >= 0 && static_cast<size_t>(written) < sizeof(line));

	DEBUGTRACE_Write(line);
}
