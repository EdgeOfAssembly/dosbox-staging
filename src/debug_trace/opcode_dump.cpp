// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Binary opcode dump subsystem.
//
// Writes a flat binary file containing the raw executed opcode bytes.  Each
// call to OpcodeDump_Write() appends num_bytes bytes read from the virtual
// machine's physical address space starting at phys_ip.
//
// The output is independent of the human-readable text trace log — it can be
// enabled alone, together with the text log, or not at all.

#include "opcode_dump.h"

#include "hardware/memory.h"

#include <cstdio>
#include <cstdint>

// ---------------------------------------------------------------------------
// File-local state
// ---------------------------------------------------------------------------

static FILE* s_fp = nullptr;

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void OpcodeDump_Init(const char* filepath)
{
	if (!filepath || filepath[0] == '\0') {
		return;
	}
	s_fp = fopen(filepath, "wb");
	if (!s_fp) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot open binary opcode dump file '%s'\n",
		        filepath);
	}
}

void OpcodeDump_Shutdown()
{
	if (s_fp) {
		fflush(s_fp);
		fclose(s_fp);
		s_fp = nullptr;
	}
}

void OpcodeDump_Write(uint32_t phys_ip, int num_bytes)
{
	if (!s_fp || num_bytes <= 0) {
		return;
	}
	for (int i = 0; i < num_bytes; ++i) {
		const uint32_t addr = (phys_ip + static_cast<uint32_t>(i)) & 0xFFFFF;
		const uint8_t  byte = mem_readb(addr);
		fwrite(&byte, 1, 1, s_fp);
	}
}
