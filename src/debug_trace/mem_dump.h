// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_MEM_DUMP_H
#define DOSBOX_MEM_DUMP_H

#include <cstdint>
#include <string>

// Guest-memory snapshot helper for reverse engineering.
//
// Hotkey dumps named regions (default: ICON stamp bank, MAP, offscreen buffer).
// Naming:
//   {game}_mem_g{gen:04d}_{name}_b{base:05X}_s{size:04X}_{seq:04d}.bin
//   (+ matching .meta sidecar)
//
// Region syntax (comma-separated), examples:
//   stamps@ds:207A+1200          — SegPhys(ds)+0x207A, size 0x1200
//   map@ds:31D4+0F00             — MAP index table
//   offscr@ds:206C->near+2000    — word at DS:206C is near offset in DS
//   farbuf@ds:1000->far+1000     — dword far ptr (off,seg) at DS:1000
//   abs@phys:B8000+07D0          — absolute physical address
//
// Defaults target ICON Quest runtime (stamp bank @ DS:207A, MAP @ DS:31D4,
// offscreen buffer pointer @ DS:206C).

struct MemDumpConfig {
	bool        enabled    = false;
	std::string dir        = "mem_dumps";
	bool        write_meta = true;
	// Mapper hotkey; default avoids screen_dump (ctrl+f10) and Shutdown (ctrl+f9).
	std::string hotkey = "ctrl+f11";
	// Region list; empty → ICON defaults.
	std::string regions = "";
};

void MemDump_Init(const MemDumpConfig& cfg);
void MemDump_Shutdown();

// From INT 21h/AH=4Bh EXEC — strip path/extension → "ICON"
void MemDump_SetGameName(const char* filename);

// Track mode-set generation so filenames align with screen dumps.
void MemDump_OnModeSet(uint8_t mode_byte);

// Manual dump (mapper hotkey).
void MemDump_Hotkey(bool pressed);

#endif // DOSBOX_MEM_DUMP_H
