// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// DOS file I/O interception logger.
// Tracks open file handles (handle -> filename) and logs reads with hex dumps.

#include "file_io_logger.h"
#include "game_trace.h"

#include "dos/dos.h"
#include "hardware/memory.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

// ---------------------------------------------------------------------------
// Handle-to-filename map
// ---------------------------------------------------------------------------

static std::unordered_map<uint16_t, std::string> s_handle_map;

// ---------------------------------------------------------------------------
// Pending read state (handle, ds_seg, dx_off saved across the DOS call)
// ---------------------------------------------------------------------------
static struct {
	bool     active       = false;
	uint16_t handle       = 0;
	uint16_t requested    = 0;
	uint16_t ds_seg       = 0;
	uint16_t dx_off       = 0;
} s_pending_read;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const char* lookup_filename(uint16_t handle)
{
	auto it = s_handle_map.find(handle);
	if (it != s_handle_map.end()) {
		return it->second.c_str();
	}
	return "<unknown>";
}

static void hex_dump(const uint8_t* data, int len, char* out, int out_size)
{
	char* wp  = out;
	char* end = out + out_size - 1;
	for (int i = 0; i < len && wp + 3 <= end; ++i) {
		wp += snprintf(wp, 4, "%02X ", data[i]);
	}
	// Trim trailing space
	if (wp > out && *(wp - 1) == ' ') {
		*(wp - 1) = '\0';
	} else {
		*wp = '\0';
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void FileIOLogger_Init()
{
	s_handle_map.clear();
	s_pending_read.active = false;
}

void FileIOLogger_Shutdown()
{
	s_handle_map.clear();
	s_pending_read.active = false;
}

void FileIOLogger_RecordHandle(const uint16_t handle, const char* filename)
{
	// DOS file handles are 0–254 (DOS_FILES - 1); reject out-of-range values
	// to prevent unbounded map growth from malformed or synthetic handles.
	if (handle >= DOS_FILES) {
		return;
	}
	if (filename && filename[0]) {
		s_handle_map[handle] = filename;
	}
}

void FileIOLogger_LogCreate(const char* filename, const uint16_t cx_attrib)
{
	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FILE CREATE: \"%s\" attributes=0x%04X",
	         DEBUGTRACE_GetElapsedMs(),
	         filename ? filename : "",
	         cx_attrib);
	DEBUGTRACE_Write(line);
}

void FileIOLogger_LogOpen(const char* filename, const uint8_t al_mode)
{
	const char* mode_str = "";
	switch (al_mode & 0x03) {
	case 0: mode_str = "read-only";  break;
	case 1: mode_str = "write-only"; break;
	case 2: mode_str = "read-write"; break;
	default: mode_str = "unknown";   break;
	}
	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FILE OPEN: \"%s\" mode=%s (AL=0x%02X)",
	         DEBUGTRACE_GetElapsedMs(),
	         filename ? filename : "",
	         mode_str,
	         al_mode);
	DEBUGTRACE_Write(line);
}

void FileIOLogger_LogClose(const uint16_t handle)
{
	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FILE CLOSE: \"%s\" (handle=%u)",
	         DEBUGTRACE_GetElapsedMs(),
	         lookup_filename(handle),
	         handle);
	DEBUGTRACE_Write(line);

	// Remove from map only after logging so the name is still available
	s_handle_map.erase(handle);
}

void FileIOLogger_LogReadPre(const uint16_t handle,
                              const uint16_t requested_bytes,
                              const uint16_t ds_seg,
                              const uint16_t dx_off)
{
	// Save state so the post-call handler can correlate
	s_pending_read.active    = true;
	s_pending_read.handle    = handle;
	s_pending_read.requested = requested_bytes;
	s_pending_read.ds_seg    = ds_seg;
	s_pending_read.dx_off    = dx_off;

	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FILE READ: \"%s\" (handle=%u) "
	         "requested=%u buffer=%04X:%04X",
	         DEBUGTRACE_GetElapsedMs(),
	         lookup_filename(handle),
	         handle,
	         requested_bytes,
	         ds_seg,
	         dx_off);
	DEBUGTRACE_Write(line);
}

void FileIOLogger_LogReadPost(const uint16_t handle,
                               const uint16_t actual_bytes,
                               const uint32_t buf_phys)
{
	if (!s_pending_read.active || s_pending_read.handle != handle) {
		s_pending_read.active = false;
		return;
	}
	s_pending_read.active = false;

	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FILE READ RESULT: \"%s\" (handle=%u) "
	         "actual=%u",
	         DEBUGTRACE_GetElapsedMs(),
	         lookup_filename(handle),
	         handle,
	         actual_bytes);
	DEBUGTRACE_Write(line);

	// Hex dump
	const int dump_bytes = std::min<int>(
	        DEBUGTRACE_FileReadHexDumpBytes(),
	        static_cast<int>(actual_bytes));
	if (dump_bytes <= 0) {
		return;
	}

	// Read from emulated memory into a local buffer (max hex-dump size is
	// capped at 512 bytes; the config default is 64).
	uint8_t buf[512];
	const int to_read = std::min(dump_bytes, (int)sizeof(buf));
	for (int i = 0; i < to_read; ++i) {
		buf[i] = mem_readb(buf_phys + i);
	}

	// Format hex dump — each byte is "XX " (3 chars) + NUL
	char hex_line[512 * 3 + 64];
	const int prefix_len = snprintf(hex_line, sizeof(hex_line),
	         "[T+%08" PRIu64 "ms] FILE DATA [first %d bytes]: ",
	         DEBUGTRACE_GetElapsedMs(),
	         to_read);
	if (prefix_len >= 0 && prefix_len < (int)sizeof(hex_line)) {
		hex_dump(buf, to_read,
		         hex_line + prefix_len,
		         (int)sizeof(hex_line) - prefix_len);
	}
	DEBUGTRACE_Write(hex_line);
}
