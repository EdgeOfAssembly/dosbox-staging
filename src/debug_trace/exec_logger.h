// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_EXEC_LOGGER_H
#define DOSBOX_EXEC_LOGGER_H

// Log a program EXEC event (INT 21h/AH=4Bh) and optionally activate tracing.
// filename : program name being loaded
// cmdline  : command-line string (may be nullptr)
void ExecLogger_Log(const char* filename, const char* cmdline);

#endif // DOSBOX_EXEC_LOGGER_H
