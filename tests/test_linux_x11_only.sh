#!/usr/bin/env bash
# Structural gate: Linux+X11-only product (drives real CMake/source files).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fail=0
check() {
  if ! eval "$2"; then
    echo "FAIL: $1"
    fail=1
  else
    echo "ok: $1"
  fi
}
check "CMake hard-fail WIN32" "rg -q 'Windows is not supported' \"$ROOT/CMakeLists.txt\""
check "CMake hard-fail APPLE" "rg -q 'macOS is not supported' \"$ROOT/CMakeLists.txt\""
check "CMake hard-fail non-Linux" "rg -q 'only Linux is supported' \"$ROOT/CMakeLists.txt\""
check "no fs_utils_win32 in misc CMake" "! rg -q 'fs_utils_win32' \"$ROOT/src/misc/CMakeLists.txt\""
check "no cdrom_win32 in dos CMake" "! rg -q 'cdrom_win32' \"$ROOT/src/dos/CMakeLists.txt\""
check "no coreaudio in midi CMake" "! rg -q 'coreaudio' \"$ROOT/src/midi/CMakeLists.txt\""
check "manymouse linux-only drivers" "rg -q 'ManyMouseDriver_evdev' \"$ROOT/src/libs/manymouse/manymouse.c\" && ! rg -q 'ManyMouseDriver_windows' \"$ROOT/src/libs/manymouse/manymouse.c\""
check "force SDL_VIDEODRIVER x11" "rg -q 'SDL_VIDEODRIVER' \"$ROOT/src/gui/sdl_gui.cpp\""
check "no WAYLAND_WMCLASS" "! rg -q 'WAYLAND_WMCLASS' \"$ROOT/src/gui/sdl_gui.cpp\""
exit $fail
