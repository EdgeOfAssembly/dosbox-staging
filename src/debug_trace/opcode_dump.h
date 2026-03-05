// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_OPCODE_DUMP_H
#define DOSBOX_OPCODE_DUMP_H

#include <cstdint>

// Initialise the binary opcode dump subsystem.
// Opens the output file. No-op if binary_opcode_dump=false.
void OpcodeDump_Init(const char* filepath);

// Shut down and flush/close the binary dump file.
void OpcodeDump_Shutdown();

// Append the raw bytes of one instruction to the binary dump.
//   phys_ip     : 20-bit physical address of the instruction start
//   num_bytes   : number of opcode bytes to write (must be > 0, typically 1)
//
// Note: the output is a sequence of first-bytes-of-each-instruction-executed.
// One byte per call is written (the opcode byte at phys_ip).  The consumer can
// perform frequency analysis, coverage mapping, etc. on this raw byte stream.
void OpcodeDump_Write(uint32_t phys_ip, int num_bytes);

#endif // DOSBOX_OPCODE_DUMP_H
