// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_INSN_LENGTH_H
#define DOSBOX_INSN_LENGTH_H

#include <cstdint>

// Return the number of bytes in the x86 real-mode instruction that starts at
// the given 20-bit physical address.  Bytes are read from the virtual machine's
// physical address space via mem_readb().
//
// The decoder handles 8086/286/386 real-mode instructions including the 0x66
// (operand-size) and 0x67 (address-size) override prefixes.  Unrecognised
// opcodes fall back to 1 so that the caller always advances by at least one
// byte and never loops forever.
//
// Return value is always in [1, 15].
int x86_insn_length_real_mode(uint32_t phys_ip);

#endif // DOSBOX_INSN_LENGTH_H
