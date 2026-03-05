// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Minimal real-mode x86 instruction-length decoder.
//
// This is intentionally a self-contained, dependency-light decoder: it only
// reads bytes from the virtual-machine's physical address space via
// mem_readb() and performs no decoding beyond what is needed to count bytes.
//
// Design goals
// ------------
// * Correctness for 8086/286/386 real-mode (16-bit default sizes).
// * Handles the 0x66 / 0x67 override prefixes so 32-bit operand/address
//   encodings encountered in 386-mode DOS programs are measured correctly.
// * Safe fall-through: any unrecognised or reserved opcode returns 1 so that
//   the caller always advances and never enters an infinite loop.
// * No heap allocation, no exceptions, no global state.

#include "insn_length.h"

#include "hardware/memory.h"

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Read one byte from the VM's physical address space (with 20-bit wrapping)
// and advance the offset counter.
static inline uint8_t fetch_byte(uint32_t base, int& off)
{
	const uint32_t addr = (base + static_cast<uint32_t>(off)) & 0xFFFFFu;
	++off;
	return mem_readb(addr);
}

// Consume the ModRM byte (and any displacement / SIB bytes that follow it)
// and add their lengths to `off`.
static void consume_modrm(uint32_t base, int& off, bool addr32)
{
	const uint8_t modrm = fetch_byte(base, off);
	const int mod = (modrm >> 6) & 0x3;
	const int rm  = modrm & 0x7;

	if (mod == 3) {
		// Register operand — no displacement.
		return;
	}

	if (!addr32) {
		// 16-bit addressing mode.
		if (mod == 0 && rm == 6) {
			off += 2; // disp16 (direct address)
		} else if (mod == 1) {
			off += 1; // disp8
		} else if (mod == 2) {
			off += 2; // disp16
		}
		// mod == 0 with rm != 6 : no displacement
	} else {
		// 32-bit addressing mode.
		if (rm == 4) {
			// SIB byte present.
			const uint8_t sib = fetch_byte(base, off);
			// If SIB base == 5 and mod == 0, there is a disp32.
			if (mod == 0 && (sib & 0x7) == 5) {
				off += 4;
			}
		}
		if (mod == 0 && rm == 5) {
			off += 4; // disp32 (direct address)
		} else if (mod == 1) {
			off += 1; // disp8
		} else if (mod == 2) {
			off += 4; // disp32
		}
	}
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

int x86_insn_length_real_mode(const uint32_t phys_ip)
{
	// `base` is the start of the instruction; `off` counts bytes consumed.
	const uint32_t base = phys_ip;
	int off = 0;

	// Default operand / address sizes for real mode (16-bit).
	bool op32   = false;
	bool addr32 = false;

	// -----------------------------------------------------------------------
	// 1.  Prefix loop
	// -----------------------------------------------------------------------
	// A real instruction can be preceded by up to 4 (architectural) or 15
	// (practical maximum including all prefix types) prefix bytes.  We loop
	// until we hit the opcode byte.  The 15-byte hard cap prevents runaway
	// on corrupted / synthetic byte streams.
	uint8_t opcode = 0;
	for (;;) {
		if (off >= 15) {
			// Safety: never return more than 15 (architectural maximum).
			return 15;
		}
		opcode = fetch_byte(base, off);
		switch (opcode) {
		case 0x26: // ES:
		case 0x2E: // CS:
		case 0x36: // SS:
		case 0x3E: // DS:
		case 0x64: // FS:  (386+)
		case 0x65: // GS:  (386+)
		case 0xF0: // LOCK
		case 0xF2: // REPNE
		case 0xF3: // REP / REPE
			continue; // consume and loop

		case 0x66: // Operand-size override (386+)
			op32 = !op32;
			continue;

		case 0x67: // Address-size override (386+)
			addr32 = !addr32;
			continue;

		default:
			goto done_prefix_loop;
		}
	}
done_prefix_loop:;

	// -----------------------------------------------------------------------
	// 2.  Two-byte escape (0x0F xx)
	// -----------------------------------------------------------------------
	if (opcode == 0x0F) {
		if (off >= 15) {
			return 15;
		}
		const uint8_t op2 = fetch_byte(base, off);
		switch (op2) {
		// Jcc near  (imm16 or imm32)
		case 0x80: case 0x81: case 0x82: case 0x83:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
			off += op32 ? 4 : 2;
			break;

		// SLDT/STR/LLDT/LTR/VERR/VERW  and  SGDT/SIDT/LGDT/LIDT/SMSW/LMSW
		case 0x00:
		case 0x01:
			consume_modrm(base, off, addr32);
			break;

		// SETcc  r/m8  — all have ModRM, no immediate
		case 0x90: case 0x91: case 0x92: case 0x93:
		case 0x94: case 0x95: case 0x96: case 0x97:
		case 0x98: case 0x99: case 0x9A: case 0x9B:
		case 0x9C: case 0x9D: case 0x9E: case 0x9F:
			consume_modrm(base, off, addr32);
			break;

		// Double-precision shifts with imm8
		case 0xA4: // SHLD r/m, r, imm8
		case 0xAC: // SHRD r/m, r, imm8
			consume_modrm(base, off, addr32);
			off += 1; // imm8
			break;

		// Most other 0F opcodes: ModRM, no immediate.
		// This is a conservative catch-all — covers BSF/BSR, MOVSX/MOVZX,
		// CMOVcc, IMUL r,r/m, etc.
		default:
			consume_modrm(base, off, addr32);
			break;
		}
		return (off <= 15) ? off : 15;
	}

	// -----------------------------------------------------------------------
	// 3.  Single-byte opcodes
	// -----------------------------------------------------------------------
	// Helper: immediate size depending on operand-size prefix.
	const int imm_sz = op32 ? 4 : 2; // imm16 or imm32

	switch (opcode) {

	// --- 1-byte instructions (no ModRM, no immediate) ---
	case 0x06: case 0x07: // PUSH ES / POP ES
	case 0x0E:            // PUSH CS
	case 0x16: case 0x17: // PUSH SS / POP SS
	case 0x1E: case 0x1F: // PUSH DS / POP DS
	case 0x27: case 0x2F: // DAA / DAS
	case 0x37: case 0x3F: // AAA / AAS
	// INC/DEC reg  (0x40–0x4F)
	case 0x40: case 0x41: case 0x42: case 0x43:
	case 0x44: case 0x45: case 0x46: case 0x47:
	case 0x48: case 0x49: case 0x4A: case 0x4B:
	case 0x4C: case 0x4D: case 0x4E: case 0x4F:
	// PUSH reg  (0x50–0x57)
	case 0x50: case 0x51: case 0x52: case 0x53:
	case 0x54: case 0x55: case 0x56: case 0x57:
	// POP reg  (0x58–0x5F)
	case 0x58: case 0x59: case 0x5A: case 0x5B:
	case 0x5C: case 0x5D: case 0x5E: case 0x5F:
	case 0x60: // PUSHA
	case 0x61: // POPA
	case 0x90: // NOP (XCHG AX,AX)
	case 0x91: case 0x92: case 0x93: // XCHG AX,reg
	case 0x94: case 0x95: case 0x96: case 0x97:
	case 0x98: // CBW
	case 0x99: // CWD
	case 0x9B: // WAIT/FWAIT
	case 0x9C: // PUSHF
	case 0x9D: // POPF
	case 0x9E: // SAHF
	case 0x9F: // LAHF
	case 0xA4: case 0xA5: // MOVS
	case 0xA6: case 0xA7: // CMPS
	case 0xAA: case 0xAB: // STOS
	case 0xAC: case 0xAD: // LODS
	case 0xAE: case 0xAF: // SCAS
	case 0xC3:            // RET (near)
	case 0xC9:            // LEAVE
	case 0xCB:            // RETF
	case 0xCC:            // INT3
	case 0xCE:            // INTO
	case 0xCF:            // IRET
	case 0xD6:            // SALC (undocumented)
	case 0xD7:            // XLAT
	case 0xEC: case 0xED: // IN AL/AX, DX
	case 0xEE: case 0xEF: // OUT DX, AL/AX
	case 0xF4:            // HLT
	case 0xF5:            // CMC
	case 0xF8:            // CLC
	case 0xF9:            // STC
	case 0xFA:            // CLI
	case 0xFB:            // STI
	case 0xFC:            // CLD
	case 0xFD:            // STD
		break; // off already at end of opcode byte

	// --- imm8 only (no ModRM) ---
	case 0x04: case 0x0C: case 0x14: case 0x1C:
	case 0x24: case 0x2C: case 0x34: case 0x3C: // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AL, imm8
	case 0x6A:            // PUSH imm8
	case 0x70: case 0x71: case 0x72: case 0x73: // Jcc short
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
	case 0xA8:            // TEST AL, imm8
	case 0xB0: case 0xB1: case 0xB2: case 0xB3: // MOV reg8, imm8
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
	case 0xCD:            // INT n
	case 0xD4:            // AAM imm8
	case 0xD5:            // AAD imm8
	case 0xE0: case 0xE1: case 0xE2: case 0xE3: // LOOP/LOOPE/LOOPNE/JCXZ
	case 0xE4: case 0xE5: // IN AL/AX, imm8
	case 0xE6: case 0xE7: // OUT imm8, AL/AX
	case 0xEB:            // JMP short  ← the opcode from the bug report
		off += 1;
		break;

	// --- imm16/32 only (no ModRM) ---
	case 0x05: case 0x0D: case 0x15: case 0x1D: // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AX, imm16/32
	case 0x25: case 0x2D: case 0x35: case 0x3D:
	case 0x68:            // PUSH imm16/32
	case 0xA9:            // TEST AX, imm16/32
	case 0xB8: case 0xB9: case 0xBA: case 0xBB: // MOV reg16/32, imm16/32
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
	case 0xE8:            // CALL near rel16/32
	case 0xE9:            // JMP  near rel16/32
		off += imm_sz;
		break;

	// --- moffs (direct memory address, no ModRM) ---
	case 0xA0: case 0xA1: // MOV AL/AX, moffs
	case 0xA2: case 0xA3: // MOV moffs, AL/AX
		off += addr32 ? 4 : 2;
		break;

	// --- JMP far: offset16 + segment16 (4 bytes), or offset32+seg16 (6 bytes) ---
	case 0xEA:
		off += op32 ? 6 : 4;
		break;

	// --- CALL far / JMP far pointer (same encoding as 0xEA for imm) ---
	case 0x9A: // CALL far  ptr16:16 or ptr16:32
		off += op32 ? 6 : 4;
		break;

	// --- RET / RETF with immediate ---
	case 0xC2: case 0xCA: // RET imm16 / RETF imm16
		off += 2;
		break;

	// --- ENTER ---
	case 0xC8:
		off += 3; // imm16 + imm8
		break;

	// --- ModRM only (no immediate) ---
	case 0x00: case 0x01: case 0x02: case 0x03: // ADD
	case 0x08: case 0x09: case 0x0A: case 0x0B: // OR
	case 0x10: case 0x11: case 0x12: case 0x13: // ADC
	case 0x18: case 0x19: case 0x1A: case 0x1B: // SBB
	case 0x20: case 0x21: case 0x22: case 0x23: // AND
	case 0x28: case 0x29: case 0x2A: case 0x2B: // SUB
	case 0x30: case 0x31: case 0x32: case 0x33: // XOR
	case 0x38: case 0x39: case 0x3A: case 0x3B: // CMP
	case 0x62:            // BOUND
	case 0x63:            // ARPL
	case 0x84: case 0x85: // TEST r/m, r
	case 0x86: case 0x87: // XCHG r/m, r
	case 0x88: case 0x89: case 0x8A: case 0x8B: // MOV
	case 0x8C: case 0x8D: case 0x8E: case 0x8F: // MOV seg, LEA, POP r/m
	case 0xC4: case 0xC5: // LES / LDS
	case 0xD0: case 0xD1: case 0xD2: case 0xD3: // Shift/Rotate
	case 0xD8: case 0xD9: case 0xDA: case 0xDB: // FPU
	case 0xDC: case 0xDD: case 0xDE: case 0xDF:
	case 0xFE: case 0xFF: // INC/DEC/CALL/JMP/PUSH r/m
		consume_modrm(base, off, addr32);
		break;

	// --- ModRM + imm8 ---
	case 0x6B:            // IMUL r, r/m, imm8
	case 0x80:            // ADD/OR/… r/m8, imm8
	case 0x83:            // ADD/OR/… r/m16/32, imm8 (sign-extended)
	case 0xC0: case 0xC1: // Shift r/m, imm8
	case 0xC6:            // MOV r/m8, imm8
		consume_modrm(base, off, addr32);
		off += 1;
		break;

	// --- ModRM + imm16/32 ---
	case 0x69:            // IMUL r, r/m, imm16/32
	case 0x81:            // ADD/OR/… r/m16/32, imm16/32
	case 0xC7:            // MOV r/m16/32, imm16/32
		consume_modrm(base, off, addr32);
		off += imm_sz;
		break;

	// --- ModRM, then conditional immediate (TEST: reg field 0 or 1) ---
	case 0xF6: {
		// TEST r/m8, imm8  vs  NOT/NEG/MUL/… r/m8 (no immediate)
		// Peek at the ModRM byte without consuming it yet.
		const uint8_t modrm_peek = mem_readb(
		        (base + static_cast<uint32_t>(off)) & 0xFFFFFu);
		const int reg_field = (modrm_peek >> 3) & 0x7;
		consume_modrm(base, off, addr32);
		if (reg_field == 0 || reg_field == 1) {
			off += 1; // imm8 for TEST
		}
		break;
	}
	case 0xF7: {
		// TEST r/m16/32, imm  vs  NOT/NEG/MUL/… r/m16/32 (no immediate)
		const uint8_t modrm_peek = mem_readb(
		        (base + static_cast<uint32_t>(off)) & 0xFFFFFu);
		const int reg_field = (modrm_peek >> 3) & 0x7;
		consume_modrm(base, off, addr32);
		if (reg_field == 0 || reg_field == 1) {
			off += imm_sz; // imm16 or imm32 for TEST
		}
		break;
	}

	default:
		// Unknown / reserved opcode — advance by 1 so callers never stall.
		break;
	}

	// Cap at the architectural maximum of 15 bytes.
	return (off <= 15) ? off : 15;
}
