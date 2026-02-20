// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_INSTRUCTION_LOGGER_H
#define DOSBOX_INSTRUCTION_LOGGER_H

#include <cstdint>

// Log the instruction currently being executed.
// cs_val : current CS register value
// ip_val : instruction pointer at the start of the instruction
void InstructionLogger_Log(uint16_t cs_val, uint16_t ip_val);

#endif // DOSBOX_INSTRUCTION_LOGGER_H
