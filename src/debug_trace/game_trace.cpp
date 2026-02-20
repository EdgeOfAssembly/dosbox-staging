// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Core tracing engine: log-file management, timing, shared state.

#include "game_trace.h"
#include "instruction_logger.h"
#include "interrupt_logger.h"
#include "file_io_logger.h"
#include "video_mode_logger.h"
#include "exec_logger.h"

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

bool g_trace_enabled       = false;
bool g_debugtrace_system_ready = false;

namespace {

// Configuration values loaded from [debugtrace]
struct TraceConfig {
	bool        enabled              = false;
	std::string logfile              = "game_trace.log";
	bool        trace_instructions   = true;
	bool        trace_interrupts     = true;
	bool        trace_file_io        = true;
	bool        trace_video_modes    = true;
	bool        auto_trace_on_exec   = true;
	std::string exclude_interrupts   = "08,1C";
	int         file_read_hex_dump   = 64;
	int         instruction_sample_rate = 1;
	int         max_log_size_mb      = 0;
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
	// Case-insensitive search through comma-separated list
	const auto& excl = g_config.exclude_interrupts;
	for (size_t pos = 0; pos < excl.size(); ) {
		size_t comma = excl.find(',', pos);
		if (comma == std::string::npos) {
			comma = excl.size();
		}
		const auto token = excl.substr(pos, comma - pos);
		if (token.size() == 2 &&
		    toupper((unsigned char)token[0]) == toupper((unsigned char)hex[0]) &&
		    toupper((unsigned char)token[1]) == toupper((unsigned char)hex[1])) {
			return true;
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

int DEBUGTRACE_FileReadHexDumpBytes()
{
	return g_config.file_read_hex_dump;
}

int DEBUGTRACE_InstructionSampleRate()
{
	return g_config.instruction_sample_rate;
}

// ---------------------------------------------------------------------------
// Integration-point functions
// ---------------------------------------------------------------------------

void DEBUGTRACE_LogInstruction(const uint16_t cs_val, const uint16_t ip_val)
{
	if (!g_config.trace_instructions) {
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

void DEBUGTRACE_LogVideoModeSwitch(const uint16_t old_mode,
                                    const uint16_t new_mode)
{
	if (!g_config.trace_video_modes) {
		return;
	}
	VideoModeLogger_Log(old_mode, new_mode);
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
	g_config.auto_trace_on_exec  = section.GetBool("auto_trace_on_exec");
	g_config.exclude_interrupts  = section.GetString("exclude_interrupts");
	g_config.file_read_hex_dump  = section.GetInt("file_read_hex_dump_bytes");
	g_config.instruction_sample_rate = section.GetInt("instruction_sample_rate");
	g_config.max_log_size_mb     = section.GetInt("max_log_size_mb");
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
	        "Maximum log file size in megabytes before auto-rotation ('0' = unlimited).");
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

	// When auto_trace_on_exec is false we start tracing immediately
	if (!g_config.auto_trace_on_exec) {
		set_epoch_now();
		g_trace_enabled = true;
		DEBUGTRACE_Write("[debugtrace] === TRACE LOGGING STARTED ===");
	}

	g_debugtrace_system_ready = true;
	FileIOLogger_Init();
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
	g_debugtrace_system_ready = false;
	s_exec_depth = 0;
	FileIOLogger_Shutdown();
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

	--s_exec_depth;

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
		DEBUGTRACE_Write("[debugtrace] === TRACE LOGGING DEACTIVATED (program exited) ===");
		// Keep g_debugtrace_system_ready=true and the log file open so
		// the user can run the game again in the same session.
	}
}
