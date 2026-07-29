# Lean posture under Xmux (Dragon Wars / 486-era)

Agent control path: **MCP / CLI → Xmux → DOSBox**. DOSBox stays the emulator
(plus debugtrace where enabled). Do not treat DOSBox control sockets as the
primary agent API.

## Speed posture (measured)

| Setting | Value | Notes |
|---------|--------|--------|
| Product | Linux + X11 only | See `docs/LINUX_X11_ONLY.md` |
| `cpu_cycles` | **8000–12000** fixed | 486-era DW under Xmux |
| `cpu_cycles_protected` | same as real-mode fixed | |
| `core` | `normal` for profile compares | dynamic is a separate experiment |
| Window | windowed 1024×768 + `xmux fill` | avoid clip past session root |

### Profile evidence (goal session)

Workload: Dragon Wars under Xmux, in-world **Purgatory**, `perf` event
`cpu-clock:u`.

| Run | Cycles | `CPU_Core_Normal_Run` share | Smoke |
|-----|--------|----------------------------|--------|
| Baseline | ~25000 (log: `CPU: Setting fixed 25000 cycles`) | **8.08%** | Purgatory OK |
| Round1 lean | **8000** | **3.36%** (~2.4× lower) | Purgatory OK |

Host multi-thread `%CPU` can still look high (mixer / render). Prefer **perf
share of `CPU_Core_Normal_Run`** as the primary compare metric.

### Proving `cpu_cycles=8000`

dosbox-staging only logs:

```text
CPU: Setting fixed N cycles. Try setting 'core = dynamic' ...
```

when **N > 20000** (`CyclesThreshold` in `src/cpu/cpu.cpp`). For 8000 that line
**does not appear**. Prove lean cycles with:

1. CLI: `--set cpu_cycles=8000 --set cpu_cycles_protected=8000`
2. Conf: `[cpu] cpu_cycles = 8000`
3. Window title: `DOSBox Staging - 8000 cycles/ms` (`xmux windows`)

## Host presets (this workstation)

```text
~/.config/dosbox/presets/
  common.conf     # mount C → ~/dos-games, mouse_capture seamless, etc.
  8086.conf / 386.conf / 486.conf / pentium.conf
  switch-era.sh   # points dosbox-staging.conf → chosen era
```

Primary conf is typically a symlink to an era preset (e.g. `486.conf`). Lean
overrides for agent runs should use a **scratch conf** + `--set`, not silently
rewrite the user’s default era without intent.

Example lean conf fragment:

```ini
[sdl]
fullscreen = false
window_position = 0,0
window_size = 1024x768

[cpu]
core = normal
cputype = 486
cpu_cycles = 8000
cpu_cycles_protected = 8000
cpu_throttle = false
```

## Xmux recipe (spectator-first)

```bash
# 1) Session
xmux start dw-play --geometry 1024x768
# SPECTATOR: xmux attach dw-play --no-reconnect

# 2) DOSBox (lean)
xmux run dw-play -- \
  /path/to/build/dosbox \
    -conf /path/to/windowed-lean.conf \
    --set cpu_cycles=8000 \
    --set cpu_cycles_protected=8000 \
    --set core=normal

# 3) Fill session root (anti-clip)
xmux fill dw-play dosbox

# 4) Agent drive (layout-aware)
xmux type dw-play -w dosbox 'cd DRGNWARS' --delay-ms 40
xmux key dw-play Return -w dosbox
xmux type dw-play -w dosbox 'DRAGON' --delay-ms 45
xmux key dw-play Return -w dosbox
# intro / menus: Escape, then b, Escape… until Purgatory
xmux screenshot dw-play -o purgatory.png

# 5) Always stop when done (avoid hot host CPU)
xmux kill dw-play
# if needed: kill dosbox / xmuxd / xmux-xvfb by exact name
```

### Black attach screen

If the spectator sees only black:

1. Confirm `xmux list` shows the session **running** and dosbox still alive.
2. `xmux fill <name> dosbox` then re-screenshot.
3. If still black: **kill session + dosbox + xmuxd + xmux-xvfb**, restart clean
   (stale Xvfb / dead client is common after long agent runs).

## Dragon Wars notes (turn-based)

- **Not real-time.** Wait after each key; screenshot after each key when
  automating so state is observable.
- Boot path used successfully: `cd DRGNWARS` → `DRAGON` → Escape intro → `b`
  (party / begin) → Escape dialogs → in-world **Purgatory**.
- Party seen in smoke: Muskels, Theb, Elendil, Cheetah.
- **Map key:** still **unproven** in automation (candidates: `Tab`, `m` /
  `shift+m`). Re-test with a shot after each probe; dismiss with Escape if a
  modal opens.
- Combat keys can fail when mouse capture steals focus; prefer seamless capture
  and `xmux key … -w dosbox` with focus.

## Config include (related feature)

Era presets use:

```ini
include = common.conf
```

See also `docs/CONFIG_INCLUDE.md` if present. Shared autoexec mounts
`/home/wizard/dos-games` as `C:` on this machine.

## Formal / tests

- Structural: `bash tests/test_linux_x11_only.sh` (required green for product cut).
- Full emulator suite / `make verify`: not the gate for this lean posture doc;
  use DW smoke + structural test + optional `perf`.

## Ops hygiene

- Never leave dosbox or orphaned `xmux-xvfb` running after a profile/play step.
- Prefer `xmux kill <session>` then exact-name kill of leftovers.
- Do not claim green smoke from a pure-black screenshot (nonzero pixel fraction
  should be clearly non-zero; Purgatory frames were ~0.80).
