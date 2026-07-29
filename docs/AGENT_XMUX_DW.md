# Agent checklist: Dragon Wars under Xmux

## Pipeline (every action)

```text
1. screenshot
2. READ the screen (do not guess)
3. decide
4. ONE key — first letter of the chosen menu line
5. ESC goes back / exits sheets
```

Character open (**1–7**) auto-pauses. Full notes: `docs/DRAGON_WARS_GAMEPLAY.md`.

## Before play

- [ ] Stack clean or intentional reuse
- [ ] Binary: `build/dosbox` (Linux+X11)
- [ ] Play conf: **25000 + dynamic**, window 1024×768, `aspect=true`, **no fill** if it clips
- [ ] Optional: desktop monitor capture + ORDERS.md (obey if running)

## Run

1. `xmux start <name> --geometry 1024x768`
2. Print: `SPECTATOR: xmux attach <name> --no-reconnect`
3. Attach (optional auto-attach on `:0`), then `xmux run … dosbox`
4. Boot: `DRAGON` → Esc/Space → **b** → Esc → Purgatory
5. Play with pipeline above; **S**ave when progress is good
6. Stop: `xmux kill <name>`; kill leftovers by exact name

## Never

- **Q** outside “Quickly fight”
- Key spam / multi-key loops without reading
- Black-frame “green” claims
