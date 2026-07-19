# Debug overlay (host-side text-cell grid)

Helps agents / RE count **steps on the text cell grid** (ICON: 40×25).

## Important

| Capture | Includes overlay? |
|---------|-------------------|
| Window screenshot / post-render image | **Yes** |
| Guest **B800** / VRAM / mem dumps | **No** (never written) |

Drawn in `SdlRenderer::PresentFrame` **after** the guest texture, **before** present/capture.

OpenGL present path: not drawn yet (SDL renderer only).

## Config (`[debugoverlay]`)

```ini
[debugoverlay]
enabled     = false          ; start with grid visible
hotkey      = ctrl+alt+g     ; toggle; 'none' to disable
force_cols  = 0              ; 0 = BIOS cols; ICON play: 40
force_rows  = 0              ; 0 = BIOS rows; ICON play: 25
major_every = 5              ; thicker line every N cells (0 = equal)
```

## Control socket

```text
OVERLAY on
OVERLAY off
OVERLAY toggle
OVERLAY status    → OK overlay=on grid=40x25 (host-only; VRAM dumps pure)
STATUS            → … overlay=on grid=40x25
```

## Build

```bash
cmake -DOPT_OPUS=OFF -B build && make -s V=0 -j$(nproc) -C build
```
