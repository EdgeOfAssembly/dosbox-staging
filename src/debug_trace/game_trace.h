// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_GAME_TRACE_H
#define DOSBOX_GAME_TRACE_H

// Main header for the dynamic debugging and reverse-engineering instrumentation
// system.  Include this header (and only this header) from integration points
// throughout the DOSBox source tree.

#include <cstdint>
#include <memory>
#include <string>

// Use the actual config types rather than redefining them
#include "config/config.h"

// ---------------------------------------------------------------------------
// Global enable flag — checked in the hot-path instruction loop.
// When false the overhead is a single boolean test.
// ---------------------------------------------------------------------------
extern bool g_trace_enabled;

// Set to true when enabled=true in the [debugtrace] section and the system has
// been successfully initialised.  Used by the EXEC hook which may fire before
// g_trace_enabled becomes true (in auto_trace_on_exec mode).
extern bool g_debugtrace_system_ready;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Called during DOSBox start-up to register the [debugtrace] config section.
void DEBUGTRACE_AddConfigSection(const ConfigPtr& conf);

// Called after config sections have been applied (DOSBOX_InitModules).
void DEBUGTRACE_Init();

// Shut down the tracing system and flush/close the log file.
void DEBUGTRACE_Shutdown();

// Returns milliseconds elapsed since the trace epoch (set at Init time or at
// the first EXEC event when auto_trace_on_exec is true).
uint64_t DEBUGTRACE_GetElapsedMs();

// ---------------------------------------------------------------------------
// Per-subsystem log helpers — called from integration points.
// Each function does nothing when tracing is globally disabled.
// ---------------------------------------------------------------------------

// Called from the CPU normal-core loop once per instruction (before SAVEIP).
//   cs_val  — current CS segment value
//   ip_val  — instruction pointer at the START of the decoded instruction
void DEBUGTRACE_LogInstruction(uint16_t cs_val, uint16_t ip_val);

// Called from the INT instruction dispatch path.
//   int_num — software interrupt number (0–255)
void DEBUGTRACE_LogInterrupt(uint8_t int_num);

// Called from INT 21h/AH=3Ch (Create file) BEFORE the DOS call is made.
void DEBUGTRACE_LogFileCreate(const char* filename, uint16_t cx_attrib);

// Called from INT 21h/AH=3Dh (Open file) BEFORE the DOS call.
void DEBUGTRACE_LogFileOpen(const char* filename, uint8_t al_mode);

// Called from INT 21h/AH=3Dh AFTER a successful open to record the mapping.
//   handle   — file handle returned by DOS
//   filename — name that was opened
void DEBUGTRACE_RecordHandleOpen(uint16_t handle, const char* filename);

// Called from INT 21h/AH=3Eh (Close file) BEFORE the DOS call.
void DEBUGTRACE_LogFileClose(uint16_t handle);

// Called from INT 21h/AH=3Fh (Read file) BEFORE the DOS read.
//   handle         — file handle
//   requested_bytes — CX value
//   ds_seg         — DS segment (buffer segment)
//   dx_off         — DX offset (buffer offset)
void DEBUGTRACE_LogFileReadPre(uint16_t handle,
                                uint16_t requested_bytes,
                                uint16_t ds_seg,
                                uint16_t dx_off);

// Called from INT 21h/AH=3Fh AFTER the DOS read.
//   handle        — file handle
//   actual_bytes  — AX after the call (bytes actually read)
//   buf_phys      — physical address of the destination buffer
void DEBUGTRACE_LogFileReadPost(uint16_t handle,
                                 uint16_t actual_bytes,
                                 uint32_t buf_phys);

// Called from INT 21h/AH=4Bh (EXEC) BEFORE program is loaded.
//   filename — program name
//   cmdline  — pointer to the command-line string (may be nullptr)
void DEBUGTRACE_LogExec(const char* filename, const char* cmdline);

// Called from INT 10h/AH=00h (Set Video Mode) BEFORE the mode switch.
//   old_mode — current mode (CurMode->mode before the switch)
//   new_mode — AL register (requested mode)
void DEBUGTRACE_LogVideoModeSwitch(uint16_t old_mode, uint16_t new_mode);

// ---------------------------------------------------------------------------
// Internal helpers used by sub-loggers (instruction, interrupt, file I/O, etc.)
// ---------------------------------------------------------------------------

// Write a single text line to the trace output.
void DEBUGTRACE_Write(const char* line);

// Returns true if the given interrupt number is in the exclusion list.
bool DEBUGTRACE_IsInterruptExcluded(uint8_t int_num);

// Accessors for per-subsystem configuration values.
bool DEBUGTRACE_AutoTraceOnExec();
int  DEBUGTRACE_FileReadHexDumpBytes();
int  DEBUGTRACE_InstructionSampleRate();

// Activate tracing (called by ExecLogger on first EXEC when auto_trace_on_exec).
void DEBUGTRACE_ActivateTrace();

#endif // DOSBOX_GAME_TRACE_H
