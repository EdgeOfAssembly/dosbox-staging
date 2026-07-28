# Config include / import

dosbox-staging (this fork) supports **including** other config files from
inside a `.conf`, so shared fragments (e.g. autoexec, mounts) can live once.

## Syntax

Any of these (case-insensitive keyword), **outside** of `[autoexec]` body
lines (global / between sections):

```ini
include = path/to/file.conf
import  = path/to/file.conf
include path/to/file.conf
@import path/to/file.conf
```

Optional quotes:

```ini
include = "common.conf"
include = '~/my-dosbox/shared.conf'
```

## Path resolution

1. Absolute path → used as-is  
2. `~/...` → expanded with `$HOME`  
3. Relative path → relative to the **directory of the file that contains the include**

Example: if `~/.config/dosbox/presets/486.conf` has `include = common.conf`,
that loads `~/.config/dosbox/presets/common.conf`.

## Semantics

- Included files are parsed with the same rules as primary / `--conf` files.
- Later settings override earlier ones (include is processed **in place**).
- **Cycles** are skipped: a file already loaded (canonical path) is not loaded again.
- Failed includes log a warning and continue.
- Nested includes are allowed.

## Example: era presets

```ini
# presets/common.conf
[autoexec]
@echo off
mount C /home/wizard/dos-games
C:

# presets/486.conf
include = common.conf

[cpu]
cputype = 486
cpu_cycles = 25000
# ...
```

## Relation to `--conf`

CLI layering still works:

```bash
dosbox --conf base.conf --conf override.conf
```

`include` is for **in-file** composition; `--conf` is for **command-line** layering.
Both can be used together.
