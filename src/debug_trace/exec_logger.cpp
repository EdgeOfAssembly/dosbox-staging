// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Program EXEC detection logger (INT 21h/AH=4Bh).
// When auto_trace_on_exec is enabled, the very first EXEC call activates full
// instruction + interrupt + file-I/O tracing.

#include "exec_logger.h"
#include "game_trace.h"

#include "cpu/registers.h"

#include <cinttypes>
#include <cstdio>

// game_trace.cpp; activates the trace epoch and sets g_trace_enabled.
// (Declared in game_trace.h)

void ExecLogger_Log(const char* filename, const char* cmdline)
{
	// Quick exit if the trace system was never initialised
	if (!g_debugtrace_system_ready) {
		return;
	}

	// Activate tracing if in auto_trace_on_exec mode
	if (DEBUGTRACE_AutoTraceOnExec()) {
		DEBUGTRACE_ActivateTrace();
	}

	// Now log the EXEC event (g_trace_enabled may have just been set)
	if (!g_trace_enabled) {
		return;
	}

	char line[512];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] === PROGRAM EXEC: \"%s\" args=\"%s\" "
	         "PSP=%04X ===",
	         DEBUGTRACE_GetElapsedMs(),
	         filename  ? filename  : "",
	         cmdline   ? cmdline   : "",
	         SegValue(ss)); // SS == PSP segment at EXEC time

	DEBUGTRACE_Write(line);

	if (DEBUGTRACE_AutoTraceOnExec()) {
		DEBUGTRACE_Write("[T+00000000ms] === FULL TRACE LOGGING ACTIVATED ===");
	}
}
