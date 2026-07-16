// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Core tracing engine: log-file management, timing, shared state.

#include "game_trace.h"
#include "instruction_logger.h"
#include "interrupt_logger.h"
#include "file_io_logger.h"
#include "video_mode_logger.h"
#include "exec_logger.h"
#include "opcode_dump.h"
#include "mem_dump.h"
#include "screen_dump.h"

#include "config/setup.h"

#include <cctype>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

bool g_trace_enabled                  = false;
bool g_debugtrace_system_ready        = false;
bool g_trace_skip_first_instruction   = false;

namespace {

// Configuration values loaded from [debugtrace]
struct TraceConfig {
	bool        enabled              = false;
	std::string logfile              = "game_trace.log";
	bool        trace_instructions   = true;
	bool        trace_interrupts     = true;
	bool        trace_file_io        = true;
	bool        trace_video_modes    = true;
	bool        auto_trace_on_exec              = true;
	bool        trace_on_interactive_exec_only  = true;
	std::string exclude_interrupts   = "08,1C";
	int         file_read_hex_dump   = 64;
	int         instruction_sample_rate = 1;
	int         max_log_size_mb      = 0;
	bool        binary_opcode_dump   = false;
	std::string binary_opcode_file   = "opcodes.bin";
	bool        binary_opcode_dump_game_only = true;
	bool        deduplicate_interrupts           = false;
	int         dedup_interrupt_window_ms        = 50;
	bool        deduplicate_instructions         = false;
	int         dedup_instruction_max_consecutive = 3;
	// Screen / VRAM dumps
	bool        screen_dump              = false;
	std::string screen_dump_dir          = "screen_dumps";
	bool        screen_dump_on_mode_set  = true;
	int         screen_dump_delay_ms     = 50;
	bool        screen_dump_full_16k     = false;
	bool        screen_dump_write_meta   = true;
	std::string screen_dump_hotkey       = "ctrl+f10";
	// Guest memory dumps (DS regions / phys)
	bool        mem_dump              = false;
	std::string mem_dump_dir          = "mem_dumps";
	bool        mem_dump_write_meta   = true;
	std::string mem_dump_hotkey       = "ctrl+f11";
	std::string mem_dump_regions = ""; // empty → ICON defaults
};

static TraceConfig g_config;

// Output file (nullptr = stdout)
static FILE* g_log_fp   = nullptr;
static bool  g_own_file = false;  // true if we opened it and must close it

// Epoch for elapsed-time calculations
static std::chrono::steady_clock::time_point g_epoch;
static bool g_epoch_set = false;

// Tracks how many non-TSR programs are currently executing under the trace.
// Incremented on each EXEC while tracing is active; decremented on AH=4Ch /
// AH=00h exit.  When it reaches zero the top-level game has returned to the
// shell and tracing is automatically deactivated.
static int s_exec_depth = 0;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void set_epoch_now()
{
	g_epoch     = std::chrono::steady_clock::now();
	g_epoch_set = true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API implementations
// ---------------------------------------------------------------------------

uint64_t DEBUGTRACE_GetElapsedMs()
{
	if (!g_epoch_set) {
		return 0;
	}
	const auto now     = std::chrono::steady_clock::now();
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
	        now - g_epoch);
	return static_cast<uint64_t>(elapsed.count());
}

// Used by sub-loggers to write a formatted line to the log.
// Declared in game_trace.h; defined here where the file handle lives.
void DEBUGTRACE_Write(const char* line)
{
	FILE* fp = g_log_fp ? g_log_fp : stdout;
	fputs(line, fp);
	fputc('\n', fp);
	// Periodic flush: every call (acceptable performance cost when tracing
	// is active; tracing is only active when the user explicitly enables it).
	fflush(fp);
}

// Check whether an interrupt number should be excluded from logging.
bool DEBUGTRACE_IsInterruptExcluded(uint8_t int_num)
{
	// Fast path for the two most common exclusions (08h / 1Ch)
	if (g_config.exclude_interrupts.empty()) {
		return false;
	}
	char hex[3];
	snprintf(hex, sizeof(hex), "%02X", int_num);

	// Walk the comma-separated exclusion list.  Both sides are upper-cased
	// before comparison so "08,1c" and "08,1C" are equivalent.
	const auto& excl = g_config.exclude_interrupts;
	for (size_t pos = 0; pos < excl.size(); ) {
		size_t comma = excl.find(',', pos);
		if (comma == std::string::npos) {
			comma = excl.size();
		}
		const auto token = excl.substr(pos, comma - pos);
		// Trim leading/trailing spaces so "08, 1C" also works
		const size_t first = token.find_first_not_of(' ');
		const size_t last  = token.find_last_not_of(' ');
		if (first != std::string::npos && (last - first + 1) == 2) {
			const auto t0 = toupper((unsigned char)token[first]);
			const auto t1 = toupper((unsigned char)token[first + 1]);
			if (t0 == (unsigned char)hex[0] && t1 == (unsigned char)hex[1]) {
				return true;
			}
		}
		pos = comma + 1;
	}
	return false;
}

bool DEBUGTRACE_TraceInstructions()
{
	return g_config.trace_instructions;
}

bool DEBUGTRACE_TraceInterrupts()
{
	return g_config.trace_interrupts;
}

bool DEBUGTRACE_TraceFileIO()
{
	return g_config.trace_file_io;
}

bool DEBUGTRACE_TraceVideoModes()
{
	return g_config.trace_video_modes;
}

bool DEBUGTRACE_AutoTraceOnExec()
{
	return g_config.auto_trace_on_exec;
}

bool DEBUGTRACE_TraceOnInteractiveExecOnly()
{
	return g_config.trace_on_interactive_exec_only;
}

int DEBUGTRACE_FileReadHexDumpBytes()
{
	return g_config.file_read_hex_dump;
}

int DEBUGTRACE_InstructionSampleRate()
{
	return g_config.instruction_sample_rate;
}

bool DEBUGTRACE_BinaryOpcodeDump()
{
	return g_config.binary_opcode_dump;
}

bool DEBUGTRACE_BinaryOpcodeDumpGameOnly()
{
	return g_config.binary_opcode_dump_game_only;
}

bool DEBUGTRACE_DeduplicateInterrupts()
{
	return g_config.deduplicate_interrupts;
}

int DEBUGTRACE_DeduplicateInterruptWindowMs()
{
	return g_config.dedup_interrupt_window_ms;
}

bool DEBUGTRACE_DeduplicateInstructions()
{
	return g_config.deduplicate_instructions;
}

int DEBUGTRACE_DeduplicateInstructionMaxConsecutive()
{
	return g_config.dedup_instruction_max_consecutive;
}

// ---------------------------------------------------------------------------
// Integration-point functions
// ---------------------------------------------------------------------------

void DEBUGTRACE_LogInstruction(const uint16_t cs_val, const uint16_t ip_val)
{
	if (!g_config.trace_instructions && !g_config.binary_opcode_dump) {
		return;
	}
	InstructionLogger_Log(cs_val, ip_val);
}

void DEBUGTRACE_LogInterrupt(const uint8_t int_num)
{
	if (!g_config.trace_interrupts) {
		return;
	}
	if (DEBUGTRACE_IsInterruptExcluded(int_num)) {
		return;
	}
	InterruptLogger_Log(int_num);
}

void DEBUGTRACE_LogFileCreate(const char* filename, const uint16_t cx_attrib)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogCreate(filename, cx_attrib);
}

void DEBUGTRACE_LogFileOpen(const char* filename, const uint8_t al_mode)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogOpen(filename, al_mode);
}

void DEBUGTRACE_RecordHandleOpen(const uint16_t handle, const char* filename)
{
	FileIOLogger_RecordHandle(handle, filename);
}

void DEBUGTRACE_LogFileClose(const uint16_t handle)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogClose(handle);
}

void DEBUGTRACE_LogFileReadPre(const uint16_t handle,
                                const uint16_t requested_bytes,
                                const uint16_t ds_seg,
                                const uint16_t dx_off)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogReadPre(handle, requested_bytes, ds_seg, dx_off);
}

void DEBUGTRACE_LogFileReadPost(const uint16_t handle,
                                 const uint16_t actual_bytes,
                                 const uint32_t buf_phys)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogReadPost(handle, actual_bytes, buf_phys);
}

void DEBUGTRACE_LogExec(const char* filename, const char* cmdline)
{
	ExecLogger_Log(filename, cmdline);
}

void DEBUGTRACE_LogFcbOpen(const uint16_t seg, const uint16_t off,
                           const uint8_t al_result)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogFcbOpen(seg, off, al_result);
}

void DEBUGTRACE_LogFcbCreate(const uint16_t seg, const uint16_t off,
                             const uint8_t al_result)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogFcbCreate(seg, off, al_result);
}

void DEBUGTRACE_LogFcbClose(const uint16_t seg, const uint16_t off,
                            const uint8_t al_result)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogFcbClose(seg, off, al_result);
}

void DEBUGTRACE_LogFcbRead(const uint16_t seg, const uint16_t off,
                           const uint8_t al_result, const uint32_t dta_phys,
                           const uint16_t rec_size)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogFcbRead(seg, off, al_result, dta_phys, rec_size);
}

void DEBUGTRACE_LogFcbBlockRead(const uint16_t seg, const uint16_t off,
                                const uint8_t al_result,
                                const uint16_t recs_requested,
                                const uint16_t recs_actual,
                                const uint32_t dta_phys,
                                const uint16_t rec_size)
{
	if (!g_config.trace_file_io) {
		return;
	}
	FileIOLogger_LogFcbBlockRead(seg, off, al_result, recs_requested,
	                             recs_actual, dta_phys, rec_size);
}

void DEBUGTRACE_LogVideoModeSwitch(const uint16_t old_mode,
                                    const uint16_t new_mode)
{
	if (!g_config.trace_video_modes) {
		return;
	}
	VideoModeLogger_Log(old_mode, new_mode);
}

void DEBUGTRACE_OnVideoModeSet(const uint8_t mode_byte)
{
	// Always track when dump subsystems are on (even mid-shell if enabled).
	// Auto VRAM dumps themselves still require g_trace_enabled (see screen_dump.cpp).
	if (g_config.screen_dump) {
		ScreenDump_OnModeSet(mode_byte);
	}
	if (g_config.mem_dump) {
		MemDump_OnModeSet(mode_byte);
	}
}

// ---------------------------------------------------------------------------
// Config section
// ---------------------------------------------------------------------------

static void init_debugtrace_settings(const SectionProp& section)
{
	g_config.enabled           = section.GetBool("enabled");
	g_config.logfile           = section.GetString("logfile");
	g_config.trace_instructions  = section.GetBool("trace_instructions");
	g_config.trace_interrupts    = section.GetBool("trace_interrupts");
	g_config.trace_file_io       = section.GetBool("trace_file_io");
	g_config.trace_video_modes   = section.GetBool("trace_video_modes");
	g_config.auto_trace_on_exec             = section.GetBool("auto_trace_on_exec");
	g_config.trace_on_interactive_exec_only = section.GetBool("trace_on_interactive_exec_only");
	g_config.exclude_interrupts  = section.GetString("exclude_interrupts");
	g_config.file_read_hex_dump  = section.GetInt("file_read_hex_dump_bytes");
	g_config.instruction_sample_rate = section.GetInt("instruction_sample_rate");
	g_config.max_log_size_mb     = section.GetInt("max_log_size_mb");
	g_config.binary_opcode_dump  = section.GetBool("binary_opcode_dump");
	g_config.binary_opcode_file  = section.GetString("binary_opcode_file");
	g_config.binary_opcode_dump_game_only = section.GetBool("binary_opcode_dump_game_only");
	g_config.deduplicate_interrupts           = section.GetBool("deduplicate_interrupts");
	g_config.dedup_interrupt_window_ms        = section.GetInt("dedup_interrupt_window_ms");
	if (g_config.dedup_interrupt_window_ms < 0) {
		g_config.dedup_interrupt_window_ms = 0;
	}
	g_config.deduplicate_instructions         = section.GetBool("deduplicate_instructions");
	g_config.dedup_instruction_max_consecutive = section.GetInt("dedup_instruction_max_consecutive");
	if (g_config.dedup_instruction_max_consecutive < 1) {
		g_config.dedup_instruction_max_consecutive = 1;
	}

	g_config.screen_dump             = section.GetBool("screen_dump");
	g_config.screen_dump_dir         = section.GetString("screen_dump_dir");
	g_config.screen_dump_on_mode_set = section.GetBool("screen_dump_on_mode_set");
	g_config.screen_dump_delay_ms    = section.GetInt("screen_dump_on_mode_set_delay_ms");
	if (g_config.screen_dump_delay_ms < 0) {
		g_config.screen_dump_delay_ms = 0;
	}
	g_config.screen_dump_full_16k   = section.GetBool("screen_dump_full_16k");
	g_config.screen_dump_write_meta = section.GetBool("screen_dump_write_meta");
	g_config.screen_dump_hotkey     = section.GetString("screen_dump_hotkey");
	if (g_config.screen_dump_hotkey.empty()) {
		g_config.screen_dump_hotkey = "ctrl+f10";
	}

	g_config.mem_dump            = section.GetBool("mem_dump");
	g_config.mem_dump_dir        = section.GetString("mem_dump_dir");
	g_config.mem_dump_write_meta = section.GetBool("mem_dump_write_meta");
	g_config.mem_dump_hotkey     = section.GetString("mem_dump_hotkey");
	if (g_config.mem_dump_hotkey.empty()) {
		g_config.mem_dump_hotkey = "ctrl+f11";
	}
	g_config.mem_dump_regions = section.GetString("mem_dump_regions");
}

static void notify_debugtrace_setting_updated([[maybe_unused]] const SectionProp& section,
                                               [[maybe_unused]] const std::string prop_name)
{
	init_debugtrace_settings(section);
	// Re-evaluate global flag
	g_trace_enabled = g_config.enabled && !g_config.auto_trace_on_exec;
}

void DEBUGTRACE_AddConfigSection(const ConfigPtr& conf)
{
	assert(conf);

	using enum Property::Changeable::Value;

	auto section = conf->AddSection("debugtrace");
	section->AddUpdateHandler(notify_debugtrace_setting_updated);

	auto pbool = section->AddBool("enabled", OnlyAtStart, false);
	pbool->SetHelp(
	        "Enable the dynamic debugging and reverse-engineering trace system\n"
	        "('false' by default).");

	auto pstring = section->AddString("logfile", OnlyAtStart, "game_trace.log");
	pstring->SetHelp(
	        "Path of the trace log file, or 'stdout' to write to the console\n"
	        "('game_trace.log' by default).");

	pbool = section->AddBool("trace_instructions", OnlyAtStart, true);
	pbool->SetHelp("Log each executed x86 instruction with register state ('true' by default).");

	pbool = section->AddBool("trace_interrupts", OnlyAtStart, true);
	pbool->SetHelp("Log software interrupt calls with register state ('true' by default).");

	pbool = section->AddBool("trace_file_io", OnlyAtStart, true);
	pbool->SetHelp(
	        "Log DOS file I/O operations (open, read, write, close) with hex dumps\n"
	        "('true' by default).");

	pbool = section->AddBool("trace_video_modes", OnlyAtStart, true);
	pbool->SetHelp("Log INT 10h video mode switches ('true' by default).");

	pbool = section->AddBool("auto_trace_on_exec", OnlyAtStart, true);
	pbool->SetHelp(
	        "Automatically start full tracing when a program is loaded via\n"
	        "INT 21h/AH=4Bh (EXEC) ('true' by default).");

	pbool = section->AddBool("trace_on_interactive_exec_only", OnlyAtStart, true);
	pbool->SetHelp(
	        "When 'true' (default), tracing only activates when the user starts a\n"
	        "program from the interactive DOS prompt.  Programs launched automatically\n"
	        "from autoexec.bat or any other batch file are ignored for activation\n"
	        "purposes.  Has no effect once tracing is already active — the game's own\n"
	        "child processes and batch scripts are always traced normally.");

	pstring = section->AddString("exclude_interrupts", OnlyAtStart, "08,1C");
	pstring->SetHelp(
	        "Comma-separated list of interrupt numbers (hex) to exclude from logging\n"
	        "('08,1C' by default — timer interrupts).");

	auto pint = section->AddInt("file_read_hex_dump_bytes", OnlyAtStart, 64);
	pint->SetHelp(
	        "Number of bytes to hex-dump for each file read operation ('64' by default,\n"
	        "set to 0 to disable hex dumps).");

	pint = section->AddInt("instruction_sample_rate", OnlyAtStart, 1);
	pint->SetHelp(
	        "Log every Nth instruction ('1' = log all, '10' = log every 10th, etc.).");

	pint = section->AddInt("max_log_size_mb", OnlyAtStart, 0);
	pint->SetHelp(
	        "Reserved for future use.  Intended to limit the log file size in megabytes\n"
	        "before auto-rotation, but this setting is currently not enforced and the\n"
	        "log size is always unlimited regardless of its value.");

	pbool = section->AddBool("binary_opcode_dump", OnlyAtStart, false);
	pbool->SetHelp(
	        "Write raw executed opcode bytes to a flat binary file.\n"
	        "Independent of 'trace_instructions' — can be enabled with or without the text log\n"
	        "('false' by default).");

	pstring = section->AddString("binary_opcode_file", OnlyAtStart, "opcodes.bin");
	pstring->SetHelp(
	        "Path of the binary opcode dump file ('opcodes.bin' by default).\n"
	        "Only used when 'binary_opcode_dump = true'.");

	pbool = section->AddBool("binary_opcode_dump_game_only", OnlyAtStart, true);
	pbool->SetHelp(
	        "When 'true' (default), the binary opcode dump excludes instructions\n"
	        "executed at or above physical address 0xA0000 (the upper memory area).\n"
	        "16-bit real-mode games never execute from this region, which contains\n"
	        "the VGA framebuffer (0xA0000-0xBFFFF), option ROMs / VGA BIOS\n"
	        "(0xC0000-0xEFFFF), and the system BIOS (0xF0000-0xFFFFF).\n"
	        "This prevents hardware interrupt handlers (INT 08h timer, INT 09h\n"
	        "keyboard, etc.) from polluting the dump with ROM code unrelated to\n"
	        "the game being traced.\n"
	        "Set to 'false' to record all executed code including ROM handlers,\n"
	        "which is useful for studying DOSBox's BIOS/option ROM implementation.");

	pbool = section->AddBool("deduplicate_interrupts", OnlyAtStart, false);
	pbool->SetHelp(
	        "Suppress repeated identical interrupt calls that occur within a short\n"
	        "time window. When the same INT number + AH + AL fires more than once\n"
	        "within 'dedup_interrupt_window_ms' milliseconds, only the first call\n"
	        "is logged; subsequent identical calls are counted and a summary line\n"
	        "is emitted when the pattern changes or the window expires.\n"
	        "('false' by default).");

	pint = section->AddInt("dedup_interrupt_window_ms", OnlyAtStart, 50);
	pint->SetHelp(
	        "Time window in milliseconds for interrupt deduplication.\n"
	        "Identical INT/AH/AL combinations within this window after the first\n"
	        "occurrence are suppressed. ('50' by default).");

	pbool = section->AddBool("deduplicate_instructions", OnlyAtStart, false);
	pbool->SetHelp(
	        "Suppress repeated identical instruction entries at the same CS:IP address.\n"
	        "When the same CS:IP is logged more than once in immediate succession\n"
	        "(within 'dedup_instruction_max_consecutive' consecutive entries),\n"
	        "only the first occurrence is logged; the rest are counted and a summary\n"
	        "line is emitted when the address changes.\n"
	        "('false' by default).");

	pint = section->AddInt("dedup_instruction_max_consecutive", OnlyAtStart, 3);
	pint->SetHelp(
	        "Maximum number of consecutive identical CS:IP entries before deduplication\n"
	        "kicks in. After this many identical entries in a row, further duplicates\n"
	        "are suppressed until a different CS:IP is seen.\n"
	        "('3' by default).");

	// --- Screen / VRAM dumps ---
	pbool = section->AddBool("screen_dump", OnlyAtStart, false);
	pbool->SetHelp(
	        "Enable VRAM / text-buffer dumps for reverse engineering ('false' by default).\n"
	        "Writes raw framebuffer bytes plus optional .meta sidecars.\n"
	        "Hotkey is set by 'screen_dump_hotkey' (default ctrl+f10).\n"
	        "Naming: {game}_g{gen}_m{mode}_b{base}_s{size}_{seq}.bin");

	pstring = section->AddString("screen_dump_dir", OnlyAtStart, "screen_dumps");
	pstring->SetHelp(
	        "Directory for screen dump files ('screen_dumps' by default).\n"
	        "Created automatically if missing.");

	pbool = section->AddBool("screen_dump_on_mode_set", OnlyAtStart, true);
	pbool->SetHelp(
	        "When screen_dump is enabled, automatically dump after each INT 10h AH=00\n"
	        "video mode switch while game tracing is active ('true' by default).\n"
	        "Use this to catch menu mode vs gameplay mode transitions.");

	pint = section->AddInt("screen_dump_on_mode_set_delay_ms", OnlyAtStart, 50);
	pint->SetHelp(
	        "Delay in milliseconds after a mode switch before dumping ('50' by default).\n"
	        "Gives the game time to paint the first frame.  Set to 0 for an immediate dump.");

	pbool = section->AddBool("screen_dump_full_16k", OnlyAtStart, false);
	pbool->SetHelp(
	        "For B800/B000 text and CGA modes, dump the full 16 KiB aperture instead of\n"
	        "only the visible page ('false' by default → mode 01h dumps 0x7D0 bytes).");

	pbool = section->AddBool("screen_dump_write_meta", OnlyAtStart, true);
	pbool->SetHelp(
	        "Write a .meta text sidecar next to each .bin dump with mode/base/size/cols\n"
	        "('true' by default).");

	pstring = section->AddString("screen_dump_hotkey", OnlyAtStart, "ctrl+f10");
	pstring->SetHelp(
	        "Keyboard shortcut for a manual VRAM dump (mapper event 'vramdump').\n"
	        "Format: [mod+][mod+]key  e.g. 'ctrl+f10', 'ctrl+alt+f12', 'f12', 'none'.\n"
	        "Modifiers: ctrl (or primary), alt, gui (win/cmd).  Keys: f1–f12, a–z, 0–9,\n"
	        "insert, delete, home, end, pageup, pagedown, printscreen, pause.\n"
	        "Default 'ctrl+f10'.  Do NOT use 'ctrl+f9' — that is DOSBox Shutdown.\n"
	        "Set to 'none' to disable the hotkey (mode-set dumps still work).");

	// --- Guest memory dumps (DS: offset regions) ---
	pbool = section->AddBool("mem_dump", OnlyAtStart, false);
	pbool->SetHelp(
	        "Enable guest-memory region dumps for reverse engineering ('false' by default).\n"
	        "Hotkey dumps configured DS/phys regions (ICON stamp bank, MAP, offscreen buffer).\n"
	        "Naming: {game}_mem_g{gen}_{name}_b{base}_s{size}_{seq}.bin");

	pstring = section->AddString("mem_dump_dir", OnlyAtStart, "mem_dumps");
	pstring->SetHelp(
	        "Directory for mem dump files ('mem_dumps' by default).\n"
	        "Created automatically if missing.");

	pbool = section->AddBool("mem_dump_write_meta", OnlyAtStart, true);
	pbool->SetHelp(
	        "Write a .meta text sidecar next to each mem dump .bin ('true' by default).");

	pstring = section->AddString("mem_dump_hotkey", OnlyAtStart, "ctrl+f11");
	pstring->SetHelp(
	        "Keyboard shortcut for a manual guest-memory dump (mapper event 'memdump').\n"
	        "Same format as screen_dump_hotkey. Default 'ctrl+f11'.\n"
	        "Do NOT use 'ctrl+f9' (Shutdown) or the same key as screen_dump_hotkey.\n"
	        "Set to 'none' to disable.");

	pstring = section->AddString("mem_dump_regions", OnlyAtStart, "");
	pstring->SetHelp(
	        "Comma-separated memory regions to dump. Empty = ICON Quest defaults:\n"
	        "  stamps@ds:207A+1200,map@ds:31D4+0F00,offscr@ds:206C->near+2000\n"
	        "Syntax per region:\n"
	        "  name@ds:OFF+SIZE          — SegPhys(DS)+OFF, SIZE bytes (hex)\n"
	        "  name@ds:OFF->near+SIZE    — word at DS:OFF is near offset in DS\n"
	        "  name@ds:OFF->far+SIZE     — far ptr (off,seg) at DS:OFF\n"
	        "  name@phys:BASE+SIZE       — absolute physical address\n"
	        "Example: stamps@ds:207A+1200,hud@ds:1000+100,vram@phys:B8000+07D0");
}

// ---------------------------------------------------------------------------
// Init / Shutdown
// ---------------------------------------------------------------------------

void DEBUGTRACE_Init()
{
	auto* section = get_section("debugtrace");
	if (!section) {
		return;
	}

	init_debugtrace_settings(*section);

	if (!g_config.enabled) {
		// Master switch is off: g_trace_enabled stays false, g_debugtrace_system_ready
		// stays false.  Every integration-point check is a single bool test — zero
		// overhead for the normal non-tracing use case.
		return;
	}

	// Open log file
	if (g_config.logfile == "stdout" || g_config.logfile.empty()) {
		g_log_fp  = stdout;
		g_own_file = false;
	} else {
		g_log_fp = fopen(g_config.logfile.c_str(), "w");
		if (!g_log_fp) {
			fprintf(stderr,
			        "[debugtrace] WARNING: cannot open log file '%s', "
			        "falling back to stdout\n",
			        g_config.logfile.c_str());
			g_log_fp  = stdout;
			g_own_file = false;
		} else {
			g_own_file = true;
		}
	}

	// Startup-tracing guarantee:
	//
	// With auto_trace_on_exec=true  (default): g_trace_enabled stays false here.
	//   Tracing ONLY becomes active when the first external program is executed
	//   via INT 21h/AH=4Bh (i.e. when the user actually runs a game).  The
	//   DOSBox shell itself starts through an internal callback — NOT via INT
	//   21h — so it never triggers this path.
	//
	// With auto_trace_on_exec=false: tracing starts immediately (below).  Use
	//   this only if you explicitly want to capture the full DOSBox session
	//   including shell activity.
	if (!g_config.auto_trace_on_exec) {
		set_epoch_now();
		g_trace_enabled = true;
		DEBUGTRACE_Write("[debugtrace] === TRACE LOGGING STARTED ===");
	}

	// Mark the system as ready.  From this point ExecLogger_Log will respond
	// to INT 21h/4Bh calls and activate tracing on the first EXEC.
	g_debugtrace_system_ready = true;
	FileIOLogger_Init();

	if (g_config.binary_opcode_dump) {
		OpcodeDump_Init(g_config.binary_opcode_file.c_str());
	}

	if (g_config.screen_dump) {
		ScreenDumpConfig sdc;
		sdc.enabled              = true;
		sdc.dir                  = g_config.screen_dump_dir;
		sdc.on_mode_set          = g_config.screen_dump_on_mode_set;
		sdc.on_mode_set_delay_ms = g_config.screen_dump_delay_ms;
		sdc.full_16k             = g_config.screen_dump_full_16k;
		sdc.write_meta           = g_config.screen_dump_write_meta;
		sdc.hotkey               = g_config.screen_dump_hotkey;
		ScreenDump_Init(sdc);
	}

	if (g_config.mem_dump) {
		MemDumpConfig mdc;
		mdc.enabled    = true;
		mdc.dir        = g_config.mem_dump_dir;
		mdc.write_meta = g_config.mem_dump_write_meta;
		mdc.hotkey     = g_config.mem_dump_hotkey;
		mdc.regions    = g_config.mem_dump_regions;
		MemDump_Init(mdc);
	}
}

void DEBUGTRACE_Shutdown()
{
	if (!g_config.enabled) {
		return;
	}

	if (g_log_fp && g_log_fp != stdout) {
		DEBUGTRACE_Write("[debugtrace] === TRACE LOGGING ENDED ===");
		fflush(g_log_fp);
		if (g_own_file) {
			fclose(g_log_fp);
		}
		g_log_fp  = nullptr;
		g_own_file = false;
	}

	g_trace_enabled = false;
	g_trace_skip_first_instruction = false;
	g_debugtrace_system_ready = false;
	s_exec_depth = 0;
	InterruptLogger_ResetDedup();
	InstructionLogger_ResetDedup();
	FileIOLogger_Shutdown();
	OpcodeDump_Shutdown();
	ScreenDump_Shutdown();
	MemDump_Shutdown();
}

// Called by ExecLogger when the first EXEC is detected (auto_trace_on_exec mode)
// ---------------------------------------------------------------------------
// Exec-depth tracking (in anonymous namespace so only this TU sees it)
// ---------------------------------------------------------------------------
void DEBUGTRACE_ActivateTrace()
{
	if (g_trace_enabled) {
		return;
	}
	set_epoch_now();
	g_trace_enabled = true;
	g_trace_skip_first_instruction = true;
	InterruptLogger_ResetDedup();
	InstructionLogger_ResetDedup();
}

void DEBUGTRACE_OnExecDepthPush()
{
	// Only track depth while tracing is active
	if (g_trace_enabled) {
		++s_exec_depth;
	}
}

void DEBUGTRACE_OnProgramTerminate(const uint8_t return_code)
{
	// Nothing to do if tracing is not currently active
	if (!g_trace_enabled) {
		return;
	}

	// When auto_trace_on_exec is false the user asked for a continuous
	// whole-session trace; depth-based deactivation does not apply.
	if (!g_config.auto_trace_on_exec) {
		char line[128];
		snprintf(line, sizeof(line),
		         "[T+%08" PRIu64 "ms] === PROGRAM TERMINATED (exit code %u) ===",
		         DEBUGTRACE_GetElapsedMs(),
		         static_cast<unsigned>(return_code));
		DEBUGTRACE_Write(line);
		return;
	}

	if (s_exec_depth > 0) {
		--s_exec_depth;
	} else {
		// Underflow guard: more terminate calls than exec pushes.  This
		// can happen in unusual DOS scenarios; clamp and log a warning.
		DEBUGTRACE_Write("[debugtrace] WARNING: program terminate without matching EXEC push");
		s_exec_depth = 0;
	}

	char line[128];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] === PROGRAM TERMINATED (exit code %u, "
	         "remaining depth %d) ===",
	         DEBUGTRACE_GetElapsedMs(),
	         static_cast<unsigned>(return_code),
	         s_exec_depth);
	DEBUGTRACE_Write(line);

	if (s_exec_depth <= 0) {
		// The top-level traced program has exited — stop logging
		s_exec_depth = 0;
		g_trace_enabled = false;
		g_trace_skip_first_instruction = false;
		DEBUGTRACE_Write("[debugtrace] === TRACE LOGGING DEACTIVATED (program exited) ===");
		// Keep g_debugtrace_system_ready=true and the log file open so
		// the user can run the game again in the same session.
	}
}
