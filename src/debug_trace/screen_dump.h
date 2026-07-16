// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_SCREEN_DUMP_H
#define DOSBOX_SCREEN_DUMP_H

#include <cstdint>
#include <string>

// Video-RAM snapshot helper for reverse engineering.
//
// Tracks BIOS mode switches, resolves phys base + visible size, and writes:
//   {game}_g{gen:04d}_m{mode:02X}_b{base:05X}_s{size:04X}_{seq:04d}.bin
//   (+ matching .meta text sidecar)
//
// Dumps run when tracing is active (after game EXEC) unless forced via hotkey
// after system init.

struct ScreenDumpConfig {
	bool        enabled              = false;
	std::string dir                  = "screen_dumps";
	bool        on_mode_set          = true;
	int         on_mode_set_delay_ms = 50; // 0 = immediate after INT 10h set
	bool        full_16k             = false; // text: dump 16 KiB B800 aperture
	bool        write_meta           = true;
	// Mapper hotkey, e.g. "ctrl+f10", "ctrl+alt+f12", "f10", "none"/"" to disable.
	// Default avoids Ctrl+F9 (DOSBox Staging Shutdown).
	std::string hotkey = "ctrl+f10";
};

void ScreenDump_Init(const ScreenDumpConfig& cfg);
void ScreenDump_Shutdown();

// From INT 21h/AH=4Bh EXEC — strip path/extension → "ICON"
void ScreenDump_SetGameName(const char* filename);

// Call AFTER INT10_SetVideoMode when tracing / dumps are enabled.
// mode_byte is AL from INT 10h AH=00 (bit 15 = don't-clear flag).
void ScreenDump_OnModeSet(uint8_t mode_byte);

// Manual dump (mapper hotkey). Works whenever the subsystem is initialised.
void ScreenDump_Hotkey(bool pressed);

// Current tracked BIOS mode (low 7 bits), or 0xFF if unknown.
uint8_t ScreenDump_CurrentMode();

#endif // DOSBOX_SCREEN_DUMP_H
