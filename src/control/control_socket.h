// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_CONTROL_SOCKET_H
#define DOSBOX_CONTROL_SOCKET_H

#include "config/config.h"
#include "config/setup.h"

// Bidirectional UNIX-domain control plane for RE / live agents.
//
// Key injection follows keypress.py --emulator-mode semantics: US layout
// mapping to DOSBox KBD_* keys (not host X11 layout). Host tools should send
// characters as DOS expects (US), not Finnish/etc. glyphs.
//
// See docs/CONTROL_SOCKET.md

void CONTROL_SOCKET_AddConfigSection(const ConfigPtr& conf);
void CONTROL_SOCKET_Init();
void CONTROL_SOCKET_Shutdown();

// Call from the main emulation loop (same place as Webserver ProcessRequests).
void CONTROL_SOCKET_Poll();

// While host-paused, the accept thread still handles HOSTUNPAUSE; Poll also
// runs from the pause loop so queued main-thread cmds can complete.

#endif
