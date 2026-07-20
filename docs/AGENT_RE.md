# Agent RE control plane

Fully automated reverse-engineering of **16-bit real-mode DOS games**.

Build: **CMake + make only** (`cmake -DOPT_OPUS=OFF -B build && make -C build -j$(nproc)`).

## Prerequisites

`[debugtrace] enabled = true` (master gate). Then:

- Instruction backlog (`cpu_backlog`)
- Agent RE: BP / WATCH / SNAPSHOT / INT ring / STEP

## Socket commands (no xdotool)

| Command | Purpose |
|---------|---------|
| `KEY` / `KEYDOWN` / `KEYUP` / `TYPE` | Input |
| `TEXT` / `B800` | Observe text VRAM |
| `TRACEBACK [n]` | Last *n* executed insns + `NOW=` regs (Capstone on agent) |
| `INTRING [n] [json]` | Last software INTs |
| `BP name CS:IP` | Execute breakpoint |
| `BPINT name INT [AH]` | INT breakpoint (optional AH) |
| `WATCH name phys:HEX[+SZ]\|ds:OFF[+SZ] [pause\|log]` | Write watch |
| `LIST` / `CLEAR` | Show / clear BP+WATCH |
| `STEP` / `CONTINUE` | Single-step / resume (host unpause) |
| `SNAPSHOT tag` | Pack: regs, traceback, int ring, B800, dumps, capture; host-pauses |
| `DIFF tagA tagB` | Compare two snapshot packs (regs + B800) |
| `HOSTPAUSE` / `HOSTUNPAUSE` | Host pause (suspends debugtrace hot path) |
| `CAPTURE` / `DUMPSCREEN` / `DUMPMEM` | Media / RE dumps |
| `OVERLAY on` | Host cell grid (screenshots only) |

## Typical agent loop

```text
OVERLAY on
… play …
HOSTPAUSE
SNAPSHOT pre_pickup
TRACEBACK 128
WATCH gold ds:????+2 pause
CONTINUE
… until trap …
SNAPSHOT post_trap
DIFF pre_pickup post_trap
HOSTUNPAUSE
```

## Config (`[debugtrace]`)

```ini
enabled = true
cpu_backlog = true
cpu_backlog_insns = 512
cpu_backlog_regs = minimal   # none|minimal|full
toggle_hotkey = ctrl+alt+d
```

Host **Alt+Pause** always suspends hot-path tracing; unpause resumes only if config still allows and session is armed.
