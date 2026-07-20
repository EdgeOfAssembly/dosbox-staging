// SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DOSBOX_AGENT_RE_H
#define DOSBOX_AGENT_RE_H

#include <cstdint>
#include <string>

// Agent-driven RE: breakpoints, write watches, step, INT ring, SNAPSHOT/DIFF.
// Gated by [debugtrace] enabled (system ready). Control socket is the UI.

// Fast checks for hot paths (false = near-zero cost).
bool AgentRe_NeedsInsnHook();
bool AgentRe_NeedsMemWatch();

// Called from normal-core before insn execute (when NeedsInsnHook).
void AgentRe_OnInstruction(uint16_t cs, uint16_t ip);

// Called after a guest byte write (when NeedsMemWatch).
void AgentRe_OnMemWrite(uint32_t phys, uint8_t old_val, uint8_t new_val);

// Software INT dispatch (always when system ready + INT ring or INT BPs).
void AgentRe_OnInterrupt(uint8_t int_num);

// --- Control plane (socket / scripts) ---
std::string AgentRe_Cmd(const std::string& line); // full command line after first word

// SNAPSHOT / DIFF helpers used by control_socket
std::string AgentRe_Snapshot(const std::string& tag);
std::string AgentRe_Diff(const std::string& tag_a, const std::string& tag_b);

// Interrupt ring dump
std::string AgentRe_IntRingFormat(int count, bool json);

// Last trap reason (for STATUS)
std::string AgentRe_LastTrapReason();

void AgentRe_Init(const std::string& snap_dir);
void AgentRe_Shutdown();
void AgentRe_ClearAll(); // clear BP/WATCH/step (not snap dir)

// Step mode: after CONTINUE, trap after next instruction
void AgentRe_RequestStep();
void AgentRe_RequestContinue(); // clear step, unpause request is separate

#endif
