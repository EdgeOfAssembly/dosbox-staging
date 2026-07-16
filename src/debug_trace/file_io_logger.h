// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_FILE_IO_LOGGER_H
#define DOSBOX_FILE_IO_LOGGER_H

#include <cstdint>

// Initialise internal handle-to-filename map.
void FileIOLogger_Init();

// Release internal state.
void FileIOLogger_Shutdown();

// Record the association of a file handle returned by DOS.
void FileIOLogger_RecordHandle(uint16_t handle, const char* filename);

// Log INT 21h/AH=3Ch (Create)
void FileIOLogger_LogCreate(const char* filename, uint16_t cx_attrib);

// Log INT 21h/AH=3Dh (Open)  — before the call
void FileIOLogger_LogOpen(const char* filename, uint8_t al_mode);

// Log INT 21h/AH=3Eh (Close) — before the call
void FileIOLogger_LogClose(uint16_t handle);

// Log INT 21h/AH=3Fh (Read)  — before the call
void FileIOLogger_LogReadPre(uint16_t handle,
                              uint16_t requested_bytes,
                              uint16_t ds_seg,
                              uint16_t dx_off);

// Log INT 21h/AH=3Fh (Read)  — after the call
void FileIOLogger_LogReadPost(uint16_t handle,
                               uint16_t actual_bytes,
                               uint32_t buf_phys);

// ---------------------------------------------------------------------------
// FCB (File Control Block) logging — DOS 1.x style I/O used by many 1980s games
// ---------------------------------------------------------------------------

// Log INT 21h/AH=0Fh (FCB Open) after the call.
//   seg/off — DS:DX of the FCB
//   al_result — AL after call (00 = success, FF = fail)
void FileIOLogger_LogFcbOpen(uint16_t seg, uint16_t off, uint8_t al_result);

// Log INT 21h/AH=16h (FCB Create) after the call.
void FileIOLogger_LogFcbCreate(uint16_t seg, uint16_t off, uint8_t al_result);

// Log INT 21h/AH=10h (FCB Close) after the call.
void FileIOLogger_LogFcbClose(uint16_t seg, uint16_t off, uint8_t al_result);

// Log INT 21h/AH=14h (sequential FCB read) after the call.
//   al_result — AL (0 success, 1 EOF, 2 DTA too small, 3 partial)
//   dta_phys  — physical address of the DTA (data landed here)
//   rec_size  — record size used for the read (0 if unknown)
void FileIOLogger_LogFcbRead(uint16_t seg, uint16_t off, uint8_t al_result,
                             uint32_t dta_phys, uint16_t rec_size);

// Log INT 21h/AH=27h (random block FCB read) after the call.
//   recs_requested / recs_actual — CX before/after (AH=27 updates CX)
void FileIOLogger_LogFcbBlockRead(uint16_t seg, uint16_t off, uint8_t al_result,
                                  uint16_t recs_requested, uint16_t recs_actual,
                                  uint32_t dta_phys, uint16_t rec_size);

#endif // DOSBOX_FILE_IO_LOGGER_H
