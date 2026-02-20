// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
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

#endif // DOSBOX_FILE_IO_LOGGER_H
