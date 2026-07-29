# Linux + X11 only (this fork)

This fork of dosbox-staging is a **Linux + X11 product**. Windows, macOS, and
Wayland are **not** supported build or runtime targets.

## Product gates

Root `CMakeLists.txt` fails configure on non-Linux hosts:

- `WIN32` → fatal: Windows not supported
- `APPLE` → fatal: macOS not supported
- `NOT LINUX` → fatal: only Linux supported

Platform-only translation units are **not listed** in CMake (win32 / macos /
coreaudio paths, etc.). ManyMouse is limited to **evdev + xinput2**.

At runtime, before SDL video init, the process forces:

```text
SDL_VIDEODRIVER=x11
```

so a session `SDL_VIDEODRIVER=wayland` cannot select Wayland.

## Structural test

```bash
bash tests/test_linux_x11_only.sh
```

Checks CMake hard-fails, excluded TUs, ManyMouse drivers, forced X11, and that
`WAYLAND_WMCLASS` does not appear in `src/gui/sdl_gui.cpp`.

## Related commits

| Commit subject | Role |
|----------------|------|
| `FEATURE v1 Linux+X11-only product cut` | CMake + source product cut |
| `FEATURE v1 Structural test for Linux+X11-only product gate` | `tests/test_linux_x11_only.sh` |
| `FIXUP v1 Drop WAYLAND_WMCLASS comment for structural gate` | Comment token vs test |

## Non-goals

- Rewriting every historical `#ifdef WIN32` body in shared sources (dead under
  the CMake gate is acceptable).
- Supporting or CI-testing Wayland / Windows / macOS after the cut.
- Removing all textual mentions of other OSes in translations or website docs.

## Build (this host)

```bash
cmake -B build -DOPT_OPUS=OFF
cmake --build build -j"$(nproc)"
# binary: build/dosbox
```

Prefer running under **Xmux** for agent + spectator workflows (see
`docs/LEAN_XMUX.md`).
