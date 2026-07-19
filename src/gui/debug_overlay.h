// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_DEBUG_OVERLAY_H
#define DOSBOX_DEBUG_OVERLAY_H

#include "config/config.h"

// Host-side presentation overlay (SDL). Drawn AFTER the guest framebuffer
// texture and NEVER written into guest VRAM — B800 / mem dumps stay pure.
// Window screenshots and post-render image capture will show the grid.

void DEBUG_OVERLAY_AddConfigSection(const ConfigPtr& conf);
void DEBUG_OVERLAY_Init();
void DEBUG_OVERLAY_Shutdown();

// Toggle visibility (mapper hotkey / control socket).
void DEBUG_OVERLAY_SetEnabled(bool on);
bool DEBUG_OVERLAY_IsEnabled();
void DEBUG_OVERLAY_Toggle();

// Call from SdlRenderer::PresentFrame after SDL_RenderCopy, before Present.
// No-op if disabled.
struct SDL_Renderer;
void DEBUG_OVERLAY_DrawSdl(SDL_Renderer* renderer);

// Call from OpenGlRenderer::PresentFrame after the guest frame is in the
// default framebuffer (viewport already set to the game draw rect).
// Uses NDC -1..1 over the current glViewport. No-op if disabled.
void DEBUG_OVERLAY_DrawOpenGL();

// Current text-grid size used for drawing (BIOS or forced).
void DEBUG_OVERLAY_GetGrid(int& cols, int& rows);

#endif
