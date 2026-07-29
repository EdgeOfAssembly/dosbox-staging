# Agent checklist: lean DW under Xmux

Short runbook for agents (no subagent gameplay loops).

## Before

- [ ] `pgrep -x dosbox` / `xmuxd` / `xmux-xvfb` clean or intentionally reused
- [ ] Binary: `build/dosbox` (Linux+X11 fork)
- [ ] Lean conf + `--set cpu_cycles=8000`

## Run

1. `xmux start <name> --geometry 1024x768`
2. Print: `SPECTATOR: xmux attach <name> --no-reconnect`
3. `xmux run <name> -- build/dosbox -conf lean.conf --set cpu_cycles=8000 …`
4. `xmux fill <name> dosbox`
5. Prove cycles: `xmux windows` shows `8000 cycles/ms`
6. Drive turn-based with **screenshot after every key**
7. Stop: `xmux kill <name>`; kill leftovers by exact process name

## After

- [ ] Notes: keys pressed, map probe result (Tab / m), any combat
- [ ] Perf note if profiled: event name, Normal_Run %, cycles proof
- [ ] No black-frame “green” claims
