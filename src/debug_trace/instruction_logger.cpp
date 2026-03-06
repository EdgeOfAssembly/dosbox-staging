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
#include "insn_length.h"
#include "opcode_dump.h"

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
// Deduplication state (file-local)
// ---------------------------------------------------------------------------
static uint16_t s_last_cs           = 0xFFFF;
static uint16_t s_last_ip           = 0xFFFF;
static int      s_consecutive_count = 0;
static uint32_t s_suppressed_insn   = 0;

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void InstructionLogger_Log(const uint16_t cs_val, const uint16_t ip_val)
{
	// Skip the very first instruction after activation — it is always a
	// BIOS ROM instruction at F000:xxxx on the INT 21h/4Bh return path,
	// not the first real game instruction.
	if (g_trace_skip_first_instruction) {
		g_trace_skip_first_instruction = false;
		return;
	}

	// Compute physical address once — used by both the binary dump and text log.
	// Apply 20-bit real-mode address wrapping so addresses above 0xFFFFF
	// wrap correctly (e.g. CS:IP = FFFF:FFF8 must not read past 1 MB).
	const uint32_t phys_base = (static_cast<uint32_t>(cs_val) << 4) & 0xFFFFF;
	const uint32_t phys_ip   = (phys_base + static_cast<uint32_t>(ip_val)) & 0xFFFFF;

	// Binary opcode dump (independent of text logging and sample rate).
	// Writes all bytes of the instruction so that the output stream is a
	// valid flat instruction sequence that ndisasm can disassemble directly.
	// Must run before the sample-rate check so it captures every executed
	// instruction regardless of the text-log sampling setting.
	if (DEBUGTRACE_BinaryOpcodeDump()) {
		// When game_only mode is active (the default), skip any instruction
		// that executes in the BIOS ROM area (physical 0xF0000–0xFFFFF).
		// This prevents timer (INT 08h) and keyboard (INT 09h) BIOS handlers
		// from polluting the dump with code unrelated to the game.
		constexpr uint32_t BIOS_ROM_START = 0xF0000u;
		const bool in_bios_rom = (phys_ip >= BIOS_ROM_START);
		if (!in_bios_rom || !DEBUGTRACE_BinaryOpcodeDumpGameOnly()) {
			const int insn_len = x86_insn_length_real_mode(phys_ip);
			OpcodeDump_Write(phys_ip, insn_len);
		}
	}

	// Instruction deduplication (text log only, not binary dump).
	if (DEBUGTRACE_TraceInstructions() && DEBUGTRACE_DeduplicateInstructions()) {
		if (cs_val == s_last_cs && ip_val == s_last_ip) {
			++s_consecutive_count;
			if (s_consecutive_count > DEBUGTRACE_DeduplicateInstructionMaxConsecutive()) {
				++s_suppressed_insn;
				// Binary dump already done above; skip text log.
				// Still advance the sample counter so the cadence
				// is not affected by dedup suppression.
				if (DEBUGTRACE_InstructionSampleRate() > 1) {
					++s_sample_counter;
					if (s_sample_counter >= DEBUGTRACE_InstructionSampleRate()) {
						s_sample_counter = 0;
					}
				}
				return;
			}
		} else {
			// Address changed — emit suppression summary if any
			if (s_suppressed_insn > 0) {
				char summary[128];
				snprintf(summary, sizeof(summary),
				         "[T+%08" PRIu64 "ms]   [%u duplicate "
				         "CS:IP=%04X:%04X instructions suppressed]",
				         DEBUGTRACE_GetElapsedMs(),
				         s_suppressed_insn,
				         s_last_cs, s_last_ip);
				DEBUGTRACE_Write(summary);
				s_suppressed_insn = 0;
			}
			s_last_cs           = cs_val;
			s_last_ip           = ip_val;
			s_consecutive_count = 1;
		}
	}

	// Sample-rate gating applies only to the text log, not the binary dump.
	const int sample_rate = DEBUGTRACE_InstructionSampleRate();
	if (sample_rate > 1) {
		++s_sample_counter;
		if (s_sample_counter < sample_rate) {
			return;
		}
		s_sample_counter = 0;
	}

	if (!DEBUGTRACE_TraceInstructions()) {
		return;
	}

	// Materialise CPU flags into reg_flags (only needed for text output).
	FillFlags();

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

void InstructionLogger_ResetDedup()
{
	s_last_cs           = 0xFFFF;
	s_last_ip           = 0xFFFF;
	s_consecutive_count = 0;
	s_suppressed_insn   = 0;
}
