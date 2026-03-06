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
  Install capstone for mnemonics and accurate instruction lengths:

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

PHYS_ADDR_SPACE = 0x100_000             # 1 MB — full 8086 physical address space
BITMAP_SIZE     = PHYS_ADDR_SPACE // 8  # 128 KB — one bit per physical address


# ---------------------------------------------------------------------------
# Optional capstone integration
# ---------------------------------------------------------------------------

try:
    import capstone                     # type: ignore
    _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    _cs.detail = False
    _HAVE_CAPSTONE = True
except ImportError:
    _HAVE_CAPSTONE = False


# ---------------------------------------------------------------------------
# Bitmap helpers
# ---------------------------------------------------------------------------

def iter_set_bits(bitmap: bytes) -> Iterator[int]:
    """Yield every physical address whose coverage bit is set, in order."""
    for byte_idx, byte_val in enumerate(bitmap):
        if byte_val == 0:
            continue
        base = byte_idx * 8
        for bit in range(8):
            if byte_val & (1 << bit):
                addr = base + bit
                if addr >= PHYS_ADDR_SPACE:
                    return
                yield addr


# ---------------------------------------------------------------------------
# Instruction length detection
# ---------------------------------------------------------------------------

def _decode_insn_length(image: bytes, addr: int) -> int:
    """Return the byte-length of the instruction at *addr*.

    Always gives Capstone the full 15-byte window so that multi-byte
    instructions (e.g. 'FE /r', 'FF /r', any ModRM opcode) are decoded
    correctly even when only the first byte has a coverage-bitmap bit.

    Falls back to 1 on any decode failure so the caller always advances.
    """
    max_len = min(15, PHYS_ADDR_SPACE - addr)
    if max_len <= 0:
        return 1

    if _HAVE_CAPSTONE:
        chunk = bytes(image[addr : addr + max_len])
        try:
            insn = next(_cs.disasm(chunk, addr, count=1), None)
        except Exception:
            insn = None
        if insn is not None:
            size = insn.size
            if 0 < size <= max_len:
                return size
        # Truly undecodable — treat as a single data byte.
        return 1

    # No Capstone: use the architectural maximum as a conservative bound.
    return max_len


def build_length_table(bitmap: bytes, image: bytes) -> list[int]:
    """Return a list[PHYS_ADDR_SPACE] mapping address → instruction length.

    Unexecuted addresses have length 0.
    """
    lengths = [0] * PHYS_ADDR_SPACE
    for addr in iter_set_bits(bitmap):
        lengths[addr] = _decode_insn_length(image, addr)
    return lengths


# ---------------------------------------------------------------------------
# Segment:offset formatting
# ---------------------------------------------------------------------------

def phys_to_seg_off(phys: int) -> str:
    """Return 'SSSS:OOOO' for a 20-bit physical address.

    Normalised paragraph-aligned form: seg = phys >> 4, off = phys & 0xF,
    so seg * 16 + off == phys exactly.
    """
    seg = (phys >> 4) & 0xFFFF
    off = phys & 0xF
    return f"{seg:04X}:{off:04X}"


# ---------------------------------------------------------------------------
# Single-instruction disassembly
# ---------------------------------------------------------------------------

def disassemble_one(image: bytes, addr: int) -> str:
    """Return a formatted disassembly string for the instruction at *addr*.

    Always passes a full 15-byte window to Capstone so that instructions
    whose operand bytes (ModRM, SIB, displacement, immediate) have no
    coverage-bitmap bit of their own are still decoded correctly.

    Return format when Capstone succeeds:
        'B8 00 00             mov ax, 0x0'

    Return format when Capstone cannot decode the byte:
        'FE                   db 0xfe  ; undecodable'

    Return format without Capstone installed:
        'B8 00 00             ; (install capstone for mnemonics)'
    """
    max_len = min(15, PHYS_ADDR_SPACE - addr)

    if _HAVE_CAPSTONE:
        chunk = bytes(image[addr : addr + max_len])
        try:
            insn = next(_cs.disasm(chunk, addr, count=1), None)
        except Exception:
            insn = None

        if insn is not None:
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
            return f"{hex_bytes:<24}  {insn.mnemonic} {insn.op_str}".rstrip()

        # Capstone could not decode — emit as a single db pseudo-instruction.
        raw = image[addr]
        return f"{raw:02X}                        db 0x{raw:02x}  ; undecodable"

    # Capstone not installed — raw hex dump only.
    hex_bytes = " ".join(f"{b:02X}" for b in image[addr : addr + max_len])
    return f"{hex_bytes:<24}  ; (install capstone for mnemonics)"


# ---------------------------------------------------------------------------
# Main disassembly loop
# ---------------------------------------------------------------------------

def disassemble(
    image: bytes,
    bitmap: bytes,
    out,
    no_gaps: bool = False,
    stats: bool = False,
) -> None:
    """Disassemble all executed instructions and write the result to *out*."""
    lengths  = build_length_table(bitmap, image)
    executed = sorted(iter_set_bits(bitmap))

    if stats:
        total_bytes  = sum(lengths[a] for a in executed)
        coverage_pct = len(executed) / PHYS_ADDR_SPACE * 100.0
        print(f"[stats] Executed instruction starts : {len(executed):,}",   file=sys.stderr)
        print(f"[stats] Executed bytes              : {total_bytes:,}",     file=sys.stderr)
        print(f"[stats] Address-space coverage      : {coverage_pct:.4f}%", file=sys.stderr)

    if not executed:
        print("; No executed instructions found in coverage bitmap.", file=out)
        return

    prev_end = -1
    for addr in executed:
        length = lengths[addr]
        if length == 0:
            continue  # should not happen

        if not no_gaps and prev_end >= 0 and addr > prev_end:
            gap = addr - prev_end
            print(f"; --- gap: {gap} byte(s) ---", file=out)

        seg_off = phys_to_seg_off(addr)
        disasm  = disassemble_one(image, addr)
        print(f"{addr:05X}  ({seg_off})  {disasm}", file=out)

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
    parser.add_argument(
        "image",
        help="Path to the 1 MB flat image file (e.g. opcodes.bin)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    parser.add_argument(
        "--no-gaps",
        action="store_true",
        help="Omit gap comments between non-contiguous addresses",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print coverage statistics to stderr",
    )
    args = parser.parse_args()

    image_path  = args.image
    bitmap_path = image_path + ".bitmap"

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
        print(
            f"warning: image size {image_size} != expected {PHYS_ADDR_SPACE} (1 MB)",
            file=sys.stderr,
        )
    if bitmap_size != BITMAP_SIZE:
        print(
            f"warning: bitmap size {bitmap_size} != expected {BITMAP_SIZE} (128 KB)",
            file=sys.stderr,
        )

    with open(image_path,  "rb") as f:
        image  = f.read()
    with open(bitmap_path, "rb") as f:
        bitmap = f.read()

    # Pad to expected sizes in case of a truncated file.
    if len(image)  < PHYS_ADDR_SPACE:
        image  = image  + bytes(PHYS_ADDR_SPACE - len(image))
    if len(bitmap) < BITMAP_SIZE:
        bitmap = bitmap + bytes(BITMAP_SIZE - len(bitmap))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            disassemble(image, bitmap, out,
                        no_gaps=args.no_gaps, stats=args.stats)
    else:
        disassemble(image, bitmap, sys.stdout,
                    no_gaps=args.no_gaps, stats=args.stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())