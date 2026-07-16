// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// DOS file I/O interception logger.
// Tracks open file handles (handle -> filename) and logs reads with hex dumps.

#include "file_io_logger.h"
#include "game_trace.h"

#include "dos/dos.h" // DOS_FCB, DOS_FCBNAME
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

// Open FCB identity (seg:off packed) → shortname for subsequent reads.
static std::unordered_map<uint32_t, std::string> s_fcb_map;

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
	s_fcb_map.clear();
	s_pending_read.active = false;
}

void FileIOLogger_Shutdown()
{
	s_handle_map.clear();
	s_fcb_map.clear();
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

// ---------------------------------------------------------------------------
// FCB helpers
// ---------------------------------------------------------------------------

// Linear key for DS:DX FCB identity in maps (seg and off are 16-bit).
static uint32_t fcb_key(const uint16_t seg, const uint16_t off)
{
	return (static_cast<uint32_t>(seg) << 16) | off;
}

// Read FCB 8.3 name from guest memory into out (e.g. "A:LA.MAP").
// Trims space padding via DOS_FCB::GetName.
static void format_fcb_name(const uint16_t seg, const uint16_t off,
                            char* out, const size_t out_sz)
{
	out[0] = '\0';
	if (out_sz < 16) {
		return;
	}
	// Prefer DOS_FCB helper for extended-FCB correctness.
	DOS_FCB fcb(seg, off);
	char raw[DOS_FCBNAME];
	fcb.GetName(raw); // "A:FILENAME.EXT" with space padding

	// Collapse spaces: A:LA      .MAP -> A:LA.MAP  (or drop drive if desired)
	// GetName format: [0]=drive letter, [1]=':', [2..9]=name, [10]='.', [11..13]=ext
	char name[9] = {};
	char ext[4]  = {};
	int ni = 0;
	for (int i = 2; i < 10 && ni < 8; ++i) {
		if (raw[i] != ' ' && raw[i] != '\0') {
			name[ni++] = raw[i];
		}
	}
	name[ni] = '\0';
	int ei = 0;
	for (int i = 11; i < 14 && ei < 3; ++i) {
		if (raw[i] != ' ' && raw[i] != '\0') {
			ext[ei++] = raw[i];
		}
	}
	ext[ei] = '\0';

	if (ext[0]) {
		snprintf(out, out_sz, "%c:%s.%s", raw[0], name, ext);
	} else {
		snprintf(out, out_sz, "%c:%s", raw[0], name);
	}
}

static const char* fcb_result_str(const uint8_t al)
{
	switch (al) {
	case 0x00: return "ok";
	case 0x01: return "EOF";
	case 0x02: return "DTA-too-small";
	case 0x03: return "partial";
	case 0xFF: return "fail";
	default:   return "other";
	}
}

static void fcb_hex_dump_dta(const uint32_t dta_phys, const uint16_t nbytes)
{
	const int dump_bytes = std::min<int>(
	        DEBUGTRACE_FileReadHexDumpBytes(),
	        static_cast<int>(nbytes));
	if (dump_bytes <= 0 || dta_phys == 0) {
		return;
	}
	uint8_t buf[512];
	const int to_read = std::min(dump_bytes, (int)sizeof(buf));
	for (int i = 0; i < to_read; ++i) {
		buf[i] = mem_readb(dta_phys + static_cast<uint32_t>(i));
	}
	char hex_line[512 * 3 + 80];
	const int prefix_len = snprintf(hex_line, sizeof(hex_line),
	         "[T+%08" PRIu64 "ms] FCB DATA [first %d bytes]: ",
	         DEBUGTRACE_GetElapsedMs(),
	         to_read);
	if (prefix_len >= 0 && prefix_len < (int)sizeof(hex_line)) {
		hex_dump(buf, to_read, hex_line + prefix_len,
		         (int)sizeof(hex_line) - prefix_len);
	}
	DEBUGTRACE_Write(hex_line);
}

void FileIOLogger_LogFcbOpen(const uint16_t seg, const uint16_t off,
                             const uint8_t al_result)
{
	char name[32];
	format_fcb_name(seg, off, name, sizeof(name));
	if (al_result == 0x00) {
		s_fcb_map[fcb_key(seg, off)] = name;
	}
	char line[320];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FCB OPEN: \"%s\" FCB=%04X:%04X result=%s (AL=0x%02X)",
	         DEBUGTRACE_GetElapsedMs(),
	         name,
	         seg,
	         off,
	         fcb_result_str(al_result),
	         al_result);
	DEBUGTRACE_Write(line);
}

void FileIOLogger_LogFcbCreate(const uint16_t seg, const uint16_t off,
                               const uint8_t al_result)
{
	char name[32];
	format_fcb_name(seg, off, name, sizeof(name));
	if (al_result == 0x00) {
		s_fcb_map[fcb_key(seg, off)] = name;
	}
	char line[320];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FCB CREATE: \"%s\" FCB=%04X:%04X result=%s (AL=0x%02X)",
	         DEBUGTRACE_GetElapsedMs(),
	         name,
	         seg,
	         off,
	         fcb_result_str(al_result),
	         al_result);
	DEBUGTRACE_Write(line);
}

void FileIOLogger_LogFcbClose(const uint16_t seg, const uint16_t off,
                              const uint8_t al_result)
{
	char name[32];
	format_fcb_name(seg, off, name, sizeof(name));
	const uint32_t key = fcb_key(seg, off);
	auto it = s_fcb_map.find(key);
	const char* shown = (it != s_fcb_map.end()) ? it->second.c_str() : name;
	char line[320];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FCB CLOSE: \"%s\" FCB=%04X:%04X result=%s (AL=0x%02X)",
	         DEBUGTRACE_GetElapsedMs(),
	         shown,
	         seg,
	         off,
	         fcb_result_str(al_result),
	         al_result);
	DEBUGTRACE_Write(line);
	s_fcb_map.erase(key);
}

void FileIOLogger_LogFcbRead(const uint16_t seg, const uint16_t off,
                             const uint8_t al_result, const uint32_t dta_phys,
                             const uint16_t rec_size)
{
	char name[32];
	format_fcb_name(seg, off, name, sizeof(name));
	const uint32_t key = fcb_key(seg, off);
	auto it = s_fcb_map.find(key);
	const char* shown = (it != s_fcb_map.end()) ? it->second.c_str() : name;

	char line[360];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FCB READ: \"%s\" FCB=%04X:%04X "
	         "recsize=%u result=%s (AL=0x%02X) DTA_phys=%05X",
	         DEBUGTRACE_GetElapsedMs(),
	         shown,
	         seg,
	         off,
	         rec_size,
	         fcb_result_str(al_result),
	         al_result,
	         dta_phys);
	DEBUGTRACE_Write(line);

	if (al_result == 0x00 || al_result == 0x03) {
		const uint16_t nbytes = rec_size ? rec_size : 128;
		fcb_hex_dump_dta(dta_phys, nbytes);
	}
}

void FileIOLogger_LogFcbBlockRead(const uint16_t seg, const uint16_t off,
                                  const uint8_t al_result,
                                  const uint16_t recs_requested,
                                  const uint16_t recs_actual,
                                  const uint32_t dta_phys,
                                  const uint16_t rec_size)
{
	char name[32];
	format_fcb_name(seg, off, name, sizeof(name));
	const uint32_t key = fcb_key(seg, off);
	auto it = s_fcb_map.find(key);
	const char* shown = (it != s_fcb_map.end()) ? it->second.c_str() : name;

	char line[400];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] FCB BLOCK-READ: \"%s\" FCB=%04X:%04X "
	         "recs=%u/%u recsize=%u result=%s (AL=0x%02X) DTA_phys=%05X",
	         DEBUGTRACE_GetElapsedMs(),
	         shown,
	         seg,
	         off,
	         recs_actual,
	         recs_requested,
	         rec_size,
	         fcb_result_str(al_result),
	         al_result,
	         dta_phys);
	DEBUGTRACE_Write(line);

	if ((al_result == 0x00 || al_result == 0x03) && recs_actual > 0) {
		const uint32_t total = static_cast<uint32_t>(recs_actual) *
		                       (rec_size ? rec_size : 128);
		fcb_hex_dump_dta(dta_phys,
		                 static_cast<uint16_t>(std::min(total, 0xFFFFu)));
	}
}
