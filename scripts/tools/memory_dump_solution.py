#!/usr/bin/env python3
# SPDX-FileCopyrightText:  2026 The DOSBox Staging Team
# SPDX-License-Identifier: GPL-2.0-or-later

"""memory_dump_solution.py — post-processor for the DOSBox Staging flat-image
opcode dump (binary_opcode_dump = true).

The binary opcode dump subsystem produces two files:

  <image>           1 MB flat image  — image[offset] == byte at physical addr offset
  <image>.bitmap    128 KB bitmap    — bit N set iff address N was an executed
                                       instruction start

This script reads both files and disassembles every address that the coverage
bitmap marks as an executed instruction start, producing clean, address-sorted
output that can be used for reverse engineering.

Usage
-----
    python3 memory_dump_solution.py [options] <image>

The bitmap is automatically located at <image>.bitmap.

Options
-------
  -o, --output FILE   Write disassembly to FILE instead of stdout.
  --no-gaps           Omit gap comments between non-contiguous executed addresses.
  --stats             Print coverage statistics to stderr.

Requirements
------------
  Python 3.8+  — no third-party packages required.
  Instruction lengths are derived by decoding instruction bytes at each
  executed address using capstone when available.  Without capstone the
  script falls back to a best-effort heuristic that caps each instruction at
  the x86 architectural maximum of 15 bytes; this heuristic does not perform
  real x86 length decoding and can be inaccurate in sparsely covered regions
  or where code and data are interleaved.  Install capstone (pip install
  capstone) for reliable instruction length detection and mnemonics:

      pip install capstone
      python3 memory_dump_solution.py opcodes.bin

Examples
--------
  # Basic disassembly of all executed instructions
  python3 memory_dump_solution.py opcodes.bin

  # Write to a file
  python3 memory_dump_solution.py -o disassembly.asm opcodes.bin

  # Show coverage statistics
  python3 memory_dump_solution.py --stats opcodes.bin
"""

from __future__ import annotations

import argparse
import sys
import os
from typing import Iterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PHYS_ADDR_SPACE = 0x100_000          # 1 MB
BITMAP_SIZE     = PHYS_ADDR_SPACE // 8  # 128 KB


# ---------------------------------------------------------------------------
# Optional capstone integration
# ---------------------------------------------------------------------------

try:
    import capstone                                      # type: ignore
    _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    _cs.detail = False
    _HAVE_CAPSTONE = True
except ImportError:
    _HAVE_CAPSTONE = False


# ---------------------------------------------------------------------------
# Minimal fallback disassembler (hex dump only, no mnemonics)
# ---------------------------------------------------------------------------

def _hex_disasm(addr: int, data: bytes, length: int) -> str:
    """Return a simple hex representation when capstone is unavailable."""
    hex_bytes = " ".join(f"{b:02X}" for b in data[addr:addr + length])
    return f"{hex_bytes:<24}  ; (install capstone for mnemonics)"


# ---------------------------------------------------------------------------
# Disassemble a single instruction
# ---------------------------------------------------------------------------

def disassemble_one(image: bytes, addr: int, length: int) -> str:
    """Return a disassembly string for the instruction at *addr*."""
    if _HAVE_CAPSTONE:
        chunk = bytes(image[addr:addr + length])
        insn = next(_cs.disasm(chunk, addr, count=1), None)  # type: ignore[call-arg]
        if insn is not None:
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)  # type: ignore[union-attr]
            return f"{hex_bytes:<24}  {insn.mnemonic} {insn.op_str}".rstrip()  # type: ignore[union-attr]
        # capstone failed — fall through to hex dump
    return _hex_disasm(addr, image, length)


# ---------------------------------------------------------------------------
# Bitmap helpers
# ---------------------------------------------------------------------------

def iter_set_bits(bitmap: bytes) -> Iterator[int]:
    """Yield every physical address whose coverage bit is set."""
    for byte_idx, byte_val in enumerate(bitmap):
        if byte_val == 0:
            continue
        base = byte_idx * 8
        for bit in range(8):
            addr = base + bit
            # Clamp to the defined physical address space to avoid out-of-range
            # accesses if the bitmap is larger than expected.
            if addr >= PHYS_ADDR_SPACE:
                return
            if byte_val & (1 << bit):
                yield addr


# ---------------------------------------------------------------------------
# Instruction length helpers
# ---------------------------------------------------------------------------

def _decode_insn_length(image: bytes, addr: int) -> int:
    """Return the length of the instruction at *addr* in *image*.

    Uses capstone when available for an exact decode.  Without capstone,
    returns a conservative fallback of min(15, remaining_bytes) — the x86
    architectural maximum — so output is bounded but may show more bytes than
    the actual instruction occupies.
    """
    # Clamp to remaining bytes and x86's architectural maximum.
    max_len = min(15, PHYS_ADDR_SPACE - addr)
    if max_len <= 0:
        return 0

    if _HAVE_CAPSTONE:
        chunk = bytes(image[addr:addr + max_len])
        try:
            insn = next(_cs.disasm(chunk, addr, count=1), None)  # type: ignore[call-arg]
        except Exception:
            insn = None
        if insn is not None:
            size = insn.size  # type: ignore[union-attr]
            if 0 < size <= max_len:
                return size
        # capstone failed for this address — fall through to conservative bound.

    # Best-effort fallback: cap at max x86 instruction length.
    return max_len


def build_length_table(bitmap: bytes, image: bytes) -> list[int]:
    """Return a list mapping physical address → instruction length (0 if not executed)."""
    lengths = [0] * PHYS_ADDR_SPACE
    for addr in iter_set_bits(bitmap):
        lengths[addr] = _decode_insn_length(image, addr)
    return lengths


# ---------------------------------------------------------------------------
# Segment:offset formatting (seg * 16 + off = phys)
# ---------------------------------------------------------------------------

def phys_to_seg_off(phys: int) -> str:
    """Format a 20-bit physical address as SSSS:OOOO (canonical min-offset form).

    Uses seg = phys >> 4, off = phys & 0xF, so seg * 16 + off == phys exactly.
    """
    seg = (phys >> 4) & 0xFFFF
    off = phys & 0xF
    return f"{seg:04X}:{off:04X}"


# ---------------------------------------------------------------------------
# Main disassembly loop
# ---------------------------------------------------------------------------

def disassemble(image: bytes,
                bitmap: bytes,
                out,
                no_gaps: bool = False,
                stats: bool = False) -> None:
    """Disassemble all executed instructions and write the result to *out*."""
    lengths = build_length_table(bitmap, image)
    executed = sorted(iter_set_bits(bitmap))

    if stats:
        total_bytes_executed = sum(lengths[a] for a in executed)
        coverage_pct = len(executed) / PHYS_ADDR_SPACE * 100.0
        print(f"[stats] Executed instruction starts : {len(executed):,}", file=sys.stderr)
        print(f"[stats] Executed bytes              : {total_bytes_executed:,}", file=sys.stderr)
        print(f"[stats] Address-space coverage      : {coverage_pct:.4f}%", file=sys.stderr)

    if not executed:
        print("; No executed instructions found in coverage bitmap.", file=out)
        return

    prev_end = -1
    for addr in executed:
        length = lengths[addr]
        if length == 0:
            # Should not happen, but be safe
            continue

        if not no_gaps and prev_end >= 0 and addr > prev_end:
            gap = addr - prev_end
            print(f"; --- gap: {gap} byte(s) --- ", file=out)

        seg_off  = phys_to_seg_off(addr)
        disasm   = disassemble_one(image, addr, length)
        hex_addr = f"{addr:05X}"
        print(f"{hex_addr}  ({seg_off})  {disasm}", file=out)

        prev_end = addr + length


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Disassemble a DOSBox Staging flat opcode-dump image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("image", help="Path to the flat image file (e.g. opcodes.bin)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write output to FILE instead of stdout")
    parser.add_argument("--no-gaps", action="store_true",
                        help="Omit gap comments between non-contiguous addresses")
    parser.add_argument("--stats", action="store_true",
                        help="Print coverage statistics to stderr")
    args = parser.parse_args()

    image_path  = args.image
    bitmap_path = image_path + ".bitmap"

    # Validate
    if not os.path.exists(image_path):
        print(f"error: image file not found: {image_path}", file=sys.stderr)
        return 1
    if not os.path.exists(bitmap_path):
        print(f"error: bitmap file not found: {bitmap_path}", file=sys.stderr)
        print(f"       (expected at {bitmap_path!r})", file=sys.stderr)
        return 1

    image_size  = os.path.getsize(image_path)
    bitmap_size = os.path.getsize(bitmap_path)

    if image_size != PHYS_ADDR_SPACE:
        print(f"warning: image size {image_size} != expected {PHYS_ADDR_SPACE} bytes",
              file=sys.stderr)
    if bitmap_size != BITMAP_SIZE:
        print(f"warning: bitmap size {bitmap_size} != expected {BITMAP_SIZE} bytes",
              file=sys.stderr)

    with open(image_path,  "rb") as f:
        image  = f.read()
    with open(bitmap_path, "rb") as f:
        bitmap = f.read()

    # Pad to expected size if truncated (shouldn't happen with a correct dump)
    if len(image)  < PHYS_ADDR_SPACE:
        image  = image  + bytes(PHYS_ADDR_SPACE - len(image))
    if len(bitmap) < BITMAP_SIZE:
        bitmap = bitmap + bytes(BITMAP_SIZE - len(bitmap))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            disassemble(image, bitmap, out, no_gaps=args.no_gaps, stats=args.stats)
    else:
        disassemble(image, bitmap, sys.stdout,
                    no_gaps=args.no_gaps, stats=args.stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
