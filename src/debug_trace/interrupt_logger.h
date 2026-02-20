// SPDX-FileCopyrightText:  2024-2025 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_INTERRUPT_LOGGER_H
#define DOSBOX_INTERRUPT_LOGGER_H

#include <cstdint>

// Log a software interrupt call.
// int_num : interrupt number (0–255)
void InterruptLogger_Log(uint8_t int_num);

#endif // DOSBOX_INTERRUPT_LOGGER_H
