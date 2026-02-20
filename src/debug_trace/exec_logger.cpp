// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Program EXEC detection logger (INT 21h/AH=4Bh).
// When auto_trace_on_exec is enabled, the very first EXEC call activates full
// instruction + interrupt + file-I/O tracing.

#include "exec_logger.h"
#include "game_trace.h"

#include "cpu/registers.h"
#include "shell/shell.h"

#include <cinttypes>
#include <cstdio>

void ExecLogger_Log(const char* filename, const char* cmdline)
{
	// Quick exit if the trace system was never initialised
	if (!g_debugtrace_system_ready) {
		return;
	}

	// --- Activation gate ---
	// We only attempt to activate tracing when it is not yet running.
	// Once g_trace_enabled is true, every EXEC (including ones from the
	// game's own batch scripts or child processes) is traced normally —
	// the interactive-only check is irrelevant at that point.
	const bool was_already_active = g_trace_enabled;
	if (!was_already_active && DEBUGTRACE_AutoTraceOnExec()) {
		bool may_activate = true;

		if (DEBUGTRACE_TraceOnInteractiveExecOnly()) {
			// Only activate when the shell is sitting at an interactive
			// prompt — i.e. no batch file (autoexec.bat, any .bat) is
			// currently being processed.
			may_activate = DOS_ShellIsInteractive();
		}

		if (may_activate) {
			DEBUGTRACE_ActivateTrace();
		}
	}

	// Nothing to do if tracing did not (or could not yet) activate
	if (!g_trace_enabled) {
		return;
	}

	// Track nesting so child-process exits don't prematurely stop tracing
	DEBUGTRACE_OnExecDepthPush();

	char line[512];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] === PROGRAM EXEC: \"%s\" args=\"%s\" "
	         "PSP=%04X ===",
	         DEBUGTRACE_GetElapsedMs(),
	         filename  ? filename  : "",
	         cmdline   ? cmdline   : "",
	         SegValue(ss)); // SS == PSP segment at EXEC time

	DEBUGTRACE_Write(line);

	// Only print the activation banner when tracing just turned on
	if (!was_already_active && DEBUGTRACE_AutoTraceOnExec()) {
		DEBUGTRACE_Write("[debugtrace] === FULL TRACE LOGGING ACTIVATED ===");
	}
}
