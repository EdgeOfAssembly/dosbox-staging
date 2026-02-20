// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

// Software interrupt call logger with human-readable descriptions for the most
// common BIOS/DOS service groups.

#include "interrupt_logger.h"
#include "game_trace.h"

#include "cpu/registers.h"
#include "cpu/lazyflags.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
// Human-readable descriptions for well-known interrupt/function combinations
// ---------------------------------------------------------------------------

static const char* describe_int21(const uint8_t ah)
{
	switch (ah) {
	case 0x00: return "Terminate Program";
	case 0x01: return "Read Char (STDIN, echo)";
	case 0x02: return "Write Char (STDOUT)";
	case 0x06: return "Direct Console I/O";
	case 0x08: return "Read Char (STDIN, no echo)";
	case 0x09: return "Write String";
	case 0x0A: return "Buffered Keyboard Input";
	case 0x0B: return "Check Keyboard Status";
	case 0x0C: return "Flush Buffer, Read Keyboard";
	case 0x0D: return "Disk Reset";
	case 0x0E: return "Select Drive";
	case 0x19: return "Get Current Drive";
	case 0x1A: return "Set DTA";
	case 0x25: return "Set Interrupt Vector";
	case 0x26: return "Create New PSP";
	case 0x2A: return "Get Date";
	case 0x2B: return "Set Date";
	case 0x2C: return "Get Time";
	case 0x2D: return "Set Time";
	case 0x2F: return "Get DTA";
	case 0x30: return "Get DOS Version";
	case 0x33: return "Extended Break Handling";
	case 0x35: return "Get Interrupt Vector";
	case 0x36: return "Get Free Disk Space";
	case 0x39: return "Create Directory";
	case 0x3A: return "Remove Directory";
	case 0x3B: return "Change Directory";
	case 0x3C: return "Create/Truncate File";
	case 0x3D: return "Open File";
	case 0x3E: return "Close File";
	case 0x3F: return "Read File/Device";
	case 0x40: return "Write File/Device";
	case 0x41: return "Delete File";
	case 0x42: return "Seek File";
	case 0x43: return "Get/Set File Attributes";
	case 0x44: return "IOCTL";
	case 0x45: return "Duplicate File Handle";
	case 0x46: return "Force Duplicate File Handle";
	case 0x47: return "Get Current Directory";
	case 0x48: return "Allocate Memory";
	case 0x49: return "Free Memory";
	case 0x4A: return "Resize Memory Block";
	case 0x4B: return "EXEC Load/Execute Program";
	case 0x4C: return "Terminate with Return Code";
	case 0x4D: return "Get Return Code";
	case 0x4E: return "Find First File";
	case 0x4F: return "Find Next File";
	case 0x56: return "Rename File";
	case 0x57: return "Get/Set File Date&Time";
	case 0x59: return "Get Extended Error";
	case 0x5A: return "Create Temp File";
	case 0x5B: return "Create New File";
	case 0x5C: return "Lock/Unlock File Region";
	case 0x5E: return "Network Functions";
	case 0x5F: return "Redirection Functions";
	case 0x62: return "Get Current PSP";
	case 0x6C: return "Extended Open/Create";
	default:   return "DOS Function";
	}
}

static const char* describe_int10(const uint8_t ah)
{
	switch (ah) {
	case 0x00: return "Set Video Mode";
	case 0x01: return "Set Text-Mode Cursor Shape";
	case 0x02: return "Set Cursor Position";
	case 0x03: return "Get Cursor Position/Shape";
	case 0x04: return "Read Light Pen";
	case 0x05: return "Set Display Page";
	case 0x06: return "Scroll Window Up";
	case 0x07: return "Scroll Window Down";
	case 0x08: return "Read Char/Attribute at Cursor";
	case 0x09: return "Write Char/Attribute at Cursor";
	case 0x0A: return "Write Char at Cursor";
	case 0x0B: return "Set Color Palette";
	case 0x0C: return "Write Graphics Pixel";
	case 0x0D: return "Read Graphics Pixel";
	case 0x0E: return "Teletype Output";
	case 0x0F: return "Get Current Video Mode";
	case 0x10: return "Set/Get Palette Registers";
	case 0x11: return "Character Generator Functions";
	case 0x12: return "Video Subsystem Configuration";
	case 0x13: return "Write String";
	case 0x1A: return "Video Display Combination";
	case 0x1B: return "Get Video State";
	case 0x1C: return "Save/Restore Video State";
	case 0x4F: return "VESA/VBE Functions";
	default:   return "Video BIOS Function";
	}
}

static const char* describe_int13(const uint8_t ah)
{
	switch (ah) {
	case 0x00: return "Reset Disk";
	case 0x01: return "Get Disk Status";
	case 0x02: return "Read Sectors";
	case 0x03: return "Write Sectors";
	case 0x04: return "Verify Sectors";
	case 0x08: return "Get Drive Parameters";
	case 0x0C: return "Seek";
	case 0x15: return "Get Drive Type";
	case 0x41: return "Check Extensions Present";
	case 0x42: return "Extended Read Sectors";
	case 0x43: return "Extended Write Sectors";
	default:   return "Disk BIOS Function";
	}
}

static const char* describe_int16(const uint8_t ah)
{
	switch (ah) {
	case 0x00: return "Read Keystroke";
	case 0x01: return "Check Keystroke Buffer";
	case 0x02: return "Get Shift Flags";
	case 0x03: return "Set Repeat Rate";
	case 0x10: return "Read Extended Keystroke";
	case 0x11: return "Check Extended Keystroke";
	case 0x12: return "Get Extended Shift Flags";
	default:   return "Keyboard BIOS Function";
	}
}

static const char* describe_int33(const uint8_t ax_lo)
{
	switch (ax_lo) {
	case 0x00: return "Mouse Reset/Get Status";
	case 0x01: return "Show Mouse Cursor";
	case 0x02: return "Hide Mouse Cursor";
	case 0x03: return "Get Mouse Position/Button";
	case 0x04: return "Set Mouse Position";
	case 0x05: return "Get Button Press Info";
	case 0x06: return "Get Button Release Info";
	case 0x07: return "Set X Range";
	case 0x08: return "Set Y Range";
	case 0x0B: return "Read Mouse Motion Counters";
	case 0x0C: return "Set Interrupt Subroutine";
	case 0x0F: return "Set Mickey/Pixel Ratio";
	default:   return "Mouse Function";
	}
}

static const char* describe_interrupt(const uint8_t int_num, const uint8_t ah,
                                       const uint8_t al)
{
	switch (int_num) {
	case 0x10: return describe_int10(ah);
	case 0x13: return describe_int13(ah);
	case 0x16: return describe_int16(ah);
	case 0x21: return describe_int21(ah);
	case 0x33: return describe_int33(al);
	case 0x08: return "Timer IRQ";
	case 0x09: return "Keyboard IRQ";
	case 0x1C: return "Timer Tick";
	case 0x2F: return "Multiplex Interrupt";
	default:   return "";
	}
}

// ---------------------------------------------------------------------------
// Public implementation
// ---------------------------------------------------------------------------

void InterruptLogger_Log(const uint8_t int_num)
{
	FillFlags();

	const uint8_t ah  = reg_ah;
	const uint8_t al  = reg_al;
	const char* desc  = describe_interrupt(int_num, ah, al);

	char desc_field[48] = "";
	if (desc && desc[0]) {
		snprintf(desc_field, sizeof(desc_field), " (%s)", desc);
	}

	char line[256];
	snprintf(line, sizeof(line),
	         "[T+%08" PRIu64 "ms] >> INT %02Xh AH=%02Xh AL=%02Xh%s  "
	         "AX=%04X BX=%04X CX=%04X DX=%04X "
	         "SI=%04X DI=%04X DS=%04X ES=%04X",
	         DEBUGTRACE_GetElapsedMs(),
	         int_num, ah, al,
	         desc_field,
	         reg_ax, reg_bx, reg_cx, reg_dx,
	         reg_si, reg_di,
	         SegValue(ds), SegValue(es));

	DEBUGTRACE_Write(line);
}
