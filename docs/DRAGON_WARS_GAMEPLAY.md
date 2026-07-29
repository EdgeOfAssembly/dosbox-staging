# Dragon Wars — agent gameplay notes (this fork / workstation)

Sources: human coaching, [classicgaming.cc controls](https://classicgaming.cc/pc/dragon-wars/controls),
live Xmux + dosbox-staging sessions (Linux+X11).

## Objective (first arc)

1. **Survive**
2. Gain **XP / levels**
3. Get **stronger** (gear, spells, stones)
4. **Escape Purgatory**

## Agent pipeline (mandatory)

```text
screenshot  →  READ what is on screen  →  decide  →  ONE key  →  (repeat)
```

- **Always read the screen** before the next key.
- **First letter** of a menu line is the action key (unless the line is only a
  parenthetical / non-action label). Examples: `G`eneral, `A`bilities,
  `A)` Gold → `A`, `F`ight, `P`ool gold.
- **ESC goes back** one level / exits the current sheet.
- Opening a character (**1–7**) **auto-pauses**; ESC exits the sheet.
- **No key spam.** Especially never spam **Q** while exploring.

## UI bars and compass

| Element | Meaning |
|---------|---------|
| **Red bars** | Hit points — 0 = **dead** |
| **Green bars** | Stamina — 0 = **stunned** that round; some returns after combat if alive |
| **Blue bars** | Spell points (casters) |
| **Red diamond arrow** | **Compass** (facing), not a map pin |

**No rest.** Spell points: dragon stones / special water / statues.  
HP and stamina recovery: **spells** (and partial stamina after combat if alive).

## Movement

| Key | Action |
|-----|--------|
| **I** | Move forward |
| **J** | Turn left 90° |
| **L** | Turn right 90° |
| **K** | Step forward (doors / secret walls) |
| **Arrows** | Also work (confirmed live; not on classicgaming page) |

## Global keys

| Key | Action |
|-----|--------|
| **1–7** | Character status (auto-pause) |
| **C** | Cast spell |
| **U** | Use item / skill / attribute |
| **X** | Experience / level-up spend |
| **S** | **Save** (one slot). May drop to DOS — relaunch `DRAGON` |
| **?** | Automap (pan with I/J/K/L) |
| **O** | Party order |
| **P** | Fight pictures on/off |
| **D** | Dismiss character (**dangerous**) |
| **Q** | **QUIT — does not save** ⚠️ |

## Character status menu (after 1–7)

```text
View...
  General overview   → G
  Abilities          → A
  Low magic          → L
  High magic         → H
  Druid magic        → D
  Sun magic          → S
  Misc magic         → M
ESC to exit
```

### Example: Muskels (slot 1) — live read

| Field | Value |
|-------|--------|
| Str / Dex / Int / Spr | 21 / 20 / 10 / 10 |
| Attack / Defense / Level / AC | 5 / 5 / 1 / 0 |
| Health / Stun | 16/16 / 16/16 |
| Power (SP) | 0/0 |
| Exp | 0 |
| Items | **A) Gold** (empty — “has no gold”) |
| Skills (Abilities) | Cave/Forest/Mountain Lore 1, Swim 1, Tracker 1, Flails 1 |
| Low magic | none |

Gold submenu when empty: **P**ool gold / **S**hare gold / **ESC** exit.

## Combat menus (first letter)

### Encounter

```text
Fight / Quickly fight / Run / Advance ahead
  F       Q (this menu only)   R    A (= Advance, not Attack!)
```

### Character turn

```text
Attack / Dodge / Block / Cast spell / Use item / … / Run
  A        …              C            …              R
```

- “Use these commands?” → **Y** / **N**
- Advance combat text: **Return** / **Space**
- **Outside combat, Q = Quit.** Only press **Q** when **Quickly fight** is visible.

## Boot path

```text
cd DRGNWARS → DRAGON → Esc/Space intro → b (begin) → Esc dialogs → Purgatory
```

If “The game is paused / Press ESC” → **ESC** once.

## Play vs profile posture

| Mode | Cycles / core | Use |
|------|----------------|-----|
| **Play / spectator** | **25000 + dynamic** | Fun, responsive |
| **Profile / lean host** | 8000–12000 + normal | Measured host share only |

SDL2 + OpenGL X11 is always used on this fork; slowness at 8k is **guest cycles**, not missing SDL.

## Xmux ops (clip / black / stop)

- Control: `xmux type/key/screenshot` into session; **MCP → xmux → app**.
- Spectator: `xmux attach <name> --no-reconnect` (print SPECTATOR line).
- Prefer **no `xmux fill`** if it stretches and **clips** the DW UI; window
  `1024x768` + `aspect=true` at `0,0`.
- Black attach while session shot is green: re-attach, resize viewer to 1024×768,
  avoid maximize crop; human Alt+Tab sometimes clears black.
- Mouse capture: title may say seamless / capture; **Ctrl+F10** or middle-click.
- Desktop monitor (optional, above play agent):
  `~/.local/share/desktop-monitor/` — `ORDERS.md` is binding when running.
- Always stop: kill dosbox, xmux, xmuxd, xmux-xvfb, capture-loop.

## Anti-patterns (learned the hard way)

- **Q** while exploring → DOS (`Illegal command: yqa` after spam)
- Treating **A** on encounter menu as Attack → it is **Advance**
- Key spam without reading → stuck menus, quit dialogs, clip confusion
- Claiming green smoke from a black screenshot
- Leaving dosbox hot after a session

## Related docs

- `docs/LEAN_XMUX.md` — cycles profile evidence
- `docs/AGENT_XMUX_DW.md` — short checklist
- `docs/LINUX_X11_ONLY.md` — product cut
- Host copies: `~/.local/share/dragon-wars/GAMEPLAY_NOTES.md`, `TACTICS.md`
