// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_VIDEO_MODE_LOGGER_H
#define DOSBOX_VIDEO_MODE_LOGGER_H

#include <cstdint>

// Log a video mode switch (INT 10h/AH=00h).
// old_mode : previously active mode number
// new_mode : requested mode number (from AL register)
void VideoModeLogger_Log(uint16_t old_mode, uint16_t new_mode);

#endif // DOSBOX_VIDEO_MODE_LOGGER_H
