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

static FILE* s_fp        = nullptr;
static bool  s_io_error  = false;  // set on first write failure; suppresses repeats

// Stream write buffer (64 KB) — reduces fwrite syscall overhead on hot paths.
static constexpr int STREAM_BUF_SIZE = 64 * 1024;
static char s_stream_buf[STREAM_BUF_SIZE];

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void OpcodeDump_Init(const char* filepath)
{
	// Close any previously-open file so init is safe to call more than once.
	OpcodeDump_Shutdown();

	if (!filepath || filepath[0] == '\0') {
		return;
	}
	s_fp       = fopen(filepath, "wb");
	s_io_error = false;
	if (!s_fp) {
		fprintf(stderr,
		        "[debugtrace] WARNING: cannot open binary opcode dump file '%s'\n",
		        filepath);
		return;
	}
	// Replace the default (line-buffered / unbuffered) stream with a large
	// full-buffer so that individual byte writes are batched by the C
	// runtime and the number of actual write(2) syscalls is minimised.
	setvbuf(s_fp, s_stream_buf, _IOFBF, STREAM_BUF_SIZE);
}

void OpcodeDump_Shutdown()
{
	if (s_fp) {
		fflush(s_fp);
		fclose(s_fp);
		s_fp       = nullptr;
		s_io_error = false;
	}
}

void OpcodeDump_Write(uint32_t phys_ip, int num_bytes)
{
	if (!s_fp || s_io_error || num_bytes <= 0) {
		return;
	}
	for (int i = 0; i < num_bytes; ++i) {
		const uint32_t addr = (phys_ip + static_cast<uint32_t>(i)) & 0xFFFFF;
		const uint8_t  byte = mem_readb(addr);
		if (fwrite(&byte, 1, 1, s_fp) != 1) {
			// Emit a one-time warning, then disable further writes to
			// avoid repeated failing syscalls on disk-full / I/O error.
			fprintf(stderr,
			        "[debugtrace] WARNING: binary opcode dump write failed "
			        "(disk full?); further writes suppressed\n");
			s_io_error = true;
			return;
		}
	}
}
