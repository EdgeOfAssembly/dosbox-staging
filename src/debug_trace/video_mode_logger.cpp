// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Video/screen mode switch logger (INT 10h/AH=00h).

#include "video_mode_logger.h"
#include "game_trace.h"

#include <cinttypes>
#include <cstdio>

// ---------------------------------------------------------------------------
// Mode description table
// ---------------------------------------------------------------------------

struct VideoModeDesc {
	uint16_t    mode;
	const char* description;
};

// Covers the most common BIOS/VGA/VESA modes a DOS game will use.
static constexpr VideoModeDesc k_mode_table[] = {
        {0x00, "40x25 16-color text (B&W)"},
        {0x01, "40x25 16-color text"},
        {0x02, "80x25 16-color text (B&W)"},
        {0x03, "80x25 16-color text"},
        {0x04, "320x200 4-color CGA"},
        {0x05, "320x200 4-color CGA (B&W)"},
        {0x06, "640x200 2-color CGA"},
        {0x07, "80x25 monochrome text (MDA/Hercules)"},
        {0x0D, "320x200 16-color EGA"},
        {0x0E, "640x200 16-color EGA"},
        {0x0F, "640x350 monochrome EGA"},
        {0x10, "640x350 16-color EGA"},
        {0x11, "640x480 2-color VGA"},
        {0x12, "640x480 16-color VGA"},
        {0x13, "320x200 256-color VGA"},
        // VESA modes
        {0x100, "640x400 256-color VESA"},
        {0x101, "640x480 256-color VESA"},
        {0x102, "800x600 16-color VESA"},
        {0x103, "800x600 256-color VESA"},
        {0x104, "1024x768 16-color VESA"},
        {0x105, "1024x768 256-color VESA"},
        {0x106, "1280x1024 16-color VESA"},
        {0x107, "1280x1024 256-color VESA"},
        {0x10D, "320x200 32K-color VESA"},
        {0x10E, "320x200 64K-color VESA"},
        {0x10F, "320x200 16M-color VESA"},
        {0x110, "640x480 32K-color VESA"},
        {0x111, "640x480 64K-color VESA"},
        {0x112, "640x480 16M-color VESA"},
        {0x113, "800x600 32K-color VESA"},
        {0x114, "800x600 64K-color VESA"},
        {0x115, "800x600 16M-color VESA"},
        {0x116, "1024x768 32K-color VESA"},
        {0x117, "1024x768 64K-color VESA"},
        {0x118, "1024x768 16M-color VESA"},
};

static const char* lookup_mode_desc(const uint16_t mode)
{
	for (const auto& entry : k_mode_table) {
		if (entry.mode == (mode & 0x7FFF)) { // mask bit 15 (don't clear)
			return entry.description;
		}
	}
	return "unknown mode";
}

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void VideoModeLogger_Log(const uint16_t old_mode, const uint16_t new_mode)
{
	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] VIDEO MODE SWITCH: %02Xh (%s) -> %02Xh (%s)",
	         DEBUGTRACE_GetElapsedMs(),
	         old_mode,
	         lookup_mode_desc(old_mode),
	         new_mode,
	         lookup_mode_desc(new_mode));
	DEBUGTRACE_Write(line);
}
