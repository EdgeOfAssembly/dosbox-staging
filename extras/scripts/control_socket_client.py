#!/usr/bin/env python3
"""Minimal client for DOSBox Staging [controlsocket] UNIX socket.

Examples:
  control_socket_client.py STATUS
  control_socket_client.py KEY y
  control_socket_client.py KEYDOWN down
  control_socket_client.py KEYUP down
  control_socket_client.py TEXT
  control_socket_client.py --sock /tmp/dosbox-control.sock TYPE hello
"""

from __future__ import annotations

import argparse
import os
import socket
import sys


def recv_reply(sock: socket.socket) -> str:
    """Read until a complete reply (single line OK/ERR, or multi-line to END)."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        text = buf.decode("utf-8", errors="replace")
        if "\nEND\n" in text or text.endswith("\nEND\n"):
            return text
        # single-line replies end with \n and no END marker expected
        if text.endswith("\n") and not text.startswith("OK TEXT") and not text.startswith(
            "OK B800"
        ):
            # multi-line headers start with OK TEXT / OK B800 then body+END
            if "\n" in text.strip() and (
                text.startswith("OK TEXT") or text.startswith("OK B800")
            ):
                continue
            return text
        if text.endswith("\n") and "\n" in text[:-1]:
            # multi-line without END yet
            if text.startswith("OK TEXT") or text.startswith("OK B800"):
                continue
            return text
    return buf.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="DOSBox control_socket client")
    ap.add_argument(
        "--sock",
        default=os.environ.get("DOSBOX_CONTROL_SOCK", "/tmp/dosbox-control.sock"),
        help="UNIX socket path (default: /tmp/dosbox-control.sock)",
    )
    ap.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command and args, e.g. KEY space  or  TYPE hello",
    )
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2

    line = " ".join(args.cmd).strip()
    if not line:
        ap.print_help()
        return 2

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(args.sock)
    except OSError as e:
        print(f"connect({args.sock}): {e}", file=sys.stderr)
        print("Is DOSBox running with [controlsocket] enabled=true?", file=sys.stderr)
        return 1

    # greeting
    greet = b""
    while b"\n" not in greet:
        chunk = s.recv(256)
        if not chunk:
            break
        greet += chunk
    sys.stderr.write(greet.decode("utf-8", errors="replace"))

    s.sendall((line + "\n").encode("utf-8"))
    reply = recv_reply(s)
    sys.stdout.write(reply)
    if not reply.endswith("\n"):
        sys.stdout.write("\n")

    try:
        s.sendall(b"QUIT\n")
        s.recv(256)
    except OSError:
        pass
    s.close()
    return 0 if reply.startswith("OK") else 1


if __name__ == "__main__":
    raise SystemExit(main())
