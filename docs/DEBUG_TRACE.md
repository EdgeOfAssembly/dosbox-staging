# DOSBox Staging — Debug Trace System

The debug trace system is a dynamic reverse-engineering instrumentation layer
built into this DOSBox Staging fork.  When enabled it silently logs every
x86 instruction executed, every software interrupt called, every DOS file
read/write, and every video mode switch to a human-readable log file.

---

## Quick Start

Add a `[debugtrace]` section to your `dosbox-staging.conf`:

```ini
[debugtrace]
enabled = true
logfile = game_trace.log
trace_instructions = true
trace_interrupts = true
trace_file_io = true
trace_video_modes = true
auto_trace_on_exec = true
trace_on_interactive_exec_only = true
exclude_interrupts = 08,1C
file_read_hex_dump_bytes = 64
instruction_sample_rate = 1
max_log_size_mb = 0
```

Launch DOSBox Staging as normal.  As soon as the game is loaded via the DOS
`EXEC` mechanism (INT 21h/AH=4Bh), tracing activates and every subsequent
event is logged to `game_trace.log`.

---

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Master switch.  Must be `true` to enable any tracing. |
| `logfile` | `game_trace.log` | Path to the log file.  Use `stdout` to print to the console. |
| `trace_instructions` | `true` | Log every executed x86 instruction with full register state. |
| `trace_interrupts` | `true` | Log every software `INT xx` call. |
| `trace_file_io` | `true` | Log DOS file open/read/close with optional hex dumps. |
| `trace_video_modes` | `true` | Log INT 10h video mode switches. |
| `auto_trace_on_exec` | `true` | Start tracing when the first program is loaded via INT 21h/AH=4Bh. |
| `trace_on_interactive_exec_only` | `true` | Only activate tracing when the user starts a program from the **interactive** DOS prompt. Programs launched from autoexec.bat or any other batch file are ignored for activation. Once the game is running, its own child processes are always traced. |
| `exclude_interrupts` | `08,1C` | Comma-separated hex list of interrupt numbers to suppress (timer IRQs by default). |
| `file_read_hex_dump_bytes` | `64` | Number of bytes to hex-dump after each file read.  `0` disables dumps. |
| `instruction_sample_rate` | `1` | Log every Nth instruction (`1` = all, `10` = every tenth, etc.). |
| `max_log_size_mb` | `0` | Maximum log file size before auto-rotation (`0` = unlimited). |

---

## Log Format

### Instruction trace

```
[T+00001234ms] CS:IP=1234:5678  BYTES=B8 00 00 XX XX XX XX XX  AX=0000 BX=1234 CX=0000 DX=00FF SI=0010 DI=0000 BP=FFFE SP=FFF0 DS=1234 ES=1234 SS=1234 FL=0246
```

- `T+NNNNNNNNms` — milliseconds since trace start (zero-padded to 8 digits).
- `CS:IP` — segment:offset of the instruction.
- `BYTES` — first 8 raw opcode bytes in hex.
- Register dump: AX BX CX DX SI DI BP SP DS ES SS FL (all 16-bit).

### Interrupt log

```
[T+00005678ms] >> INT 21h AH=3Fh AL=00h (Read File/Device)  AX=3F00 BX=0005 CX=0200 DX=1000 SI=0000 DI=0000 DS=1234 ES=5678
```

Human-readable descriptions are included for INT 10h (video), INT 13h (disk),
INT 16h (keyboard), INT 21h (DOS), and INT 33h (mouse).

### File I/O log

```
[T+00006000ms] FILE OPEN: "LEVEL1.DAT" mode=read-only (AL=0x00)
[T+00006001ms] FILE READ: "LEVEL1.DAT" (handle=5) requested=512 buffer=1234:1000
[T+00006001ms] FILE READ RESULT: "LEVEL1.DAT" (handle=5) actual=512
[T+00006001ms] FILE DATA [first 64 bytes]: 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 ...
[T+00006500ms] FILE CLOSE: "LEVEL1.DAT" (handle=5)
```

The system tracks open handles (INT 21h/AH=3Ch create, AH=3Dh open, AH=3Eh
close) so filenames are always shown alongside their handles.

### Video mode switch log

```
[T+00003000ms] VIDEO MODE SWITCH: 03h (80x25 16-color text) -> 13h (320x200 256-color VGA)
```

### EXEC / program launch

```
[T+00000000ms] === PROGRAM EXEC: "GAME.EXE" args="" PSP=1234 ===
[T+00000000ms] === FULL TRACE LOGGING ACTIVATED ===
```

---

## Use Cases

### Finding proprietary file format headers

Set `trace_file_io = true` and `file_read_hex_dump_bytes = 256`.  Run the
game until it loads the first level.  Search the log for `FILE DATA` entries
— the hex bytes immediately after the first read of a `.DAT` / `.LVL` / etc.
file show the raw magic bytes and header structure.

### Tracing game engine initialization

Set `auto_trace_on_exec = true` and keep `trace_instructions = false`
(instruction tracing produces enormous logs).  Enable `trace_interrupts = true`
and `trace_file_io = true`.  The log will show the exact sequence of files
opened, memory allocated (INT 21h/AH=48h), and video modes set during startup.

### Identifying VGA mode switching patterns

Set `trace_video_modes = true` and run the game.  Each `VIDEO MODE SWITCH`
line shows the transition from text/EGA mode to the game's target VGA mode,
with a timestamp that can be correlated with other log entries.

### Assembly-level reverse engineering

Enable `trace_instructions = true` with `instruction_sample_rate = 1`.
Warning: this generates very large logs (millions of lines per second).
Consider using `instruction_sample_rate = 100` (log every 100th instruction)
to get a statistical sample, or set `auto_trace_on_exec = false` and manually
toggle tracing at a specific point using a debugger breakpoint.

### Correlating game events with interrupts

Enable `trace_interrupts = true` with `exclude_interrupts = 08,1C,70,71,72,73,74,75,76,77`
to suppress all hardware IRQs.  The remaining entries show only software
interrupts generated by game code, making it easy to spot patterns in DOS
service usage.

---

## Performance Impact

| Configuration | Approximate overhead |
|---------------|---------------------|
| `enabled = false` | Zero — a single `bool` test per instruction. |
| `enabled = true, trace_instructions = false` | < 1% — only interrupts and file I/O are logged. |
| `enabled = true, trace_instructions = true, sample_rate = 1` | Very high — expect 10–100× slowdown.  Log file grows at ~1–5 MB/s. |
| `enabled = true, trace_instructions = true, sample_rate = 1000` | Low — roughly 1–5% overhead; 1/1000 of the instruction volume. |

The log file is flushed on every write when tracing is active (to ensure
nothing is lost if DOSBox crashes).  For maximum performance with instruction
tracing, set `logfile = /dev/shm/game_trace.log` (Linux tmpfs) or use an SSD.

---

## Notes

- Only the **normal CPU core** is instrumented.  The dynamic recompiler cores
  (dyn-x86, dynrec) do not produce instruction traces.
- The instruction log prints the raw opcode bytes; use a standalone disassembler
  (e.g. `ndisasm`, `objdump`, Ghidra, IDA) to decode them.
- The `PSP` field in the EXEC log line shows the **stack segment** value at the
  time of the EXEC call, which may differ from the actual PSP segment by a
  small amount depending on DOS internals.
