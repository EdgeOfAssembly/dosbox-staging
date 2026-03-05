// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_OPCODE_DUMP_H
#define DOSBOX_OPCODE_DUMP_H

#include <cstdint>

// Initialise the binary opcode dump subsystem.
//
// Creates two memory-mapped files:
//   <filepath>         — 1 MB flat image of the 8086 physical address space.
//                        image[offset] == the byte at physical address offset.
//   <filepath>.bitmap  — 128 KB coverage bitmap (1 bit per physical address).
//                        Bit N is set iff address N was an executed instruction start.
//
// Both files are pre-zeroed and mapped with PROT_READ|PROT_WRITE / MAP_SHARED
// (POSIX) or CreateFileMapping/MapViewOfFile (Win32).
// No-op if binary_opcode_dump=false or filepath is empty.
void OpcodeDump_Init(const char* filepath);

// Flush and close both mapped files.
void OpcodeDump_Shutdown();

// Record one executed instruction into the flat image and coverage bitmap.
//   phys_ip   : 20-bit physical address of the instruction start
//   num_bytes : byte length of the instruction (must be > 0)
//
// Writes instruction bytes into the flat image at their exact physical offsets
// and sets the coverage bitmap bit for phys_ip.  Operations are idempotent:
// re-executing the same address writes the same bytes to the same location.
void OpcodeDump_Write(uint32_t phys_ip, int num_bytes);

#endif // DOSBOX_OPCODE_DUMP_H
