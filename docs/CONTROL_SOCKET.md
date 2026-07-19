# Control socket (agent / RE control plane)

Bidirectional **UNIX-domain socket** for live control of DOSBox Staging without
X11 or xdotool. Keys are injected via `KEYBOARD_AddKey` using a **US /
keypress `--emulator-mode`** map (not the host keyboard layout).

Also writes a **PID file** next to the socket so agents can detect a live
instance and clean up stale sockets after a crash.

## Config (`[controlsocket]`)

Section names may only contain letters and digits (no underscores).

```ini
[controlsocket]
enabled     = true
path        = /tmp/dosbox-control.sock
pidfile     =            # empty or "auto" → /tmp/dosbox-control.pid
                         # "none" / "off" / "false" → no pid file
key_hold_ms = 30         # KEY tap hold before release
```

On start (when enabled):

1. If `path` exists and `pidfile` names a **live** other PID → refuse to bind.
2. Otherwise unlink a **stale** socket/pidfile, bind, write pidfile, accept.

On shutdown: unlink socket and pidfile.

## Protocol

Line-oriented, UTF-8 / ASCII. Server greets with:

```text
OK control_socket 1 ready
```

Commands (case-insensitive keyword; replies end with `\n`, multi-line blocks end with `END\n`):

| Command | Action |
|---------|--------|
| `HELLO` / `PING` | Banner / `OK PONG` |
| `STATUS` | `OK pid=… sock=… pidfile=… hold_ms=…` |
| `KEY <name>` / `TAP <name>` | Press+release (optional shift for `A`–`Z`) |
| `KEYDOWN <name>` / `KEYUP <name>` | Hold / release (movement, etc.) |
| `TYPE <text>` | Type string as US keys |
| `TEXT` | ASCII map of visible text VRAM (CP437 → simple glyphs) |
| `B800` | Hex dump of text page (char,attr pairs) |
| `DUMPSCREEN` | Same as mapper screen_dump hotkey |
| `DUMPMEM` | Same as mapper mem_dump hotkey |
| `CAPTURE [grouped\|rendered\|raw]` | Staging PNG (same as F5 shortcuts; includes host overlay) |
| `HOSTPAUSE` / `HOSTUNPAUSE` | Host pause loop (suspends debugtrace); unpause via socket or Alt+Pause |
| `TRACETOGGLE` | Flip live tracing on/off (respects `enabled=` config) |
| `OVERLAY [on\|off\|toggle\|status]` | Host cell grid |
| `HELP` | List commands |
| `QUIT` | Close client |

No xdotool required for keys, dumps, screenshots, or pause.

### Key names

- Letters `a`–`z`, `A`–`Z` (shift), digits, common US symbols
- Named: `space`, `esc`, `enter`, `tab`, `backspace`, arrows, `f1`–`f12`,
  `home`/`end`/`pageup`/`pagedown`/`insert`/`delete`
- Modifiers: `shift`/`lshift`/`rshift`, `ctrl`/`lctrl`/`rctrl`, `alt`/`lalt`/`ralt`
- Keypad: `kp0`–`kp9`, `kpenter`, `kpup`/`kpdown`/`kpleft`/`kpright` (ICON F1 rose)

Same idea as `/tmp/keypress` **emulator mode**: send what **DOS** expects (US),
not Finnish/host glyphs.

## Quick test

```bash
# conf snippet enabled, then:
printf 'STATUS\nTEXT\nKEY y\nQUIT\n' | nc -U /tmp/dosbox-control.sock
# or:
python3 extras/scripts/control_socket_client.py STATUS
python3 extras/scripts/control_socket_client.py KEY space
```

## Build (CMake + make)

From the tree root (e.g. `/tmp/dosbox-staging`):

```bash
cmake -DOPT_OPUS=OFF -B build && make -s V=0 -j$(nproc) -C build
```

Re-run the same after these changes so CMake picks up `src/control/` and
rebuilds `libdosboxcommon` + `dosbox`. Install as you usually do.

## Security

The socket is a local **full control** surface (keys + dumps). Keep it under
`/tmp` with default permissions, do not expose via SSH forward to untrusted
hosts, and disable (`enabled = false`) for normal play.
