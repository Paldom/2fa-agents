#!/usr/bin/env python3
"""Prove a 2FA code source works BEFORE touching a login form. Standard library only.

Reaching the 2FA prompt and only then discovering the code command is broken costs a
login attempt, and a few of those trip rate limiting or lock the account. This runs
the whole chain against nothing at all.

Checks:
  1. the command runs, exits 0, and prints something code-shaped
  2. two runs inside one time step return the SAME code (proves real TOTP, not noise)
  3. it is fast enough to finish inside a 30-second window
  4. the host clock is within tolerance of network time

The code itself is never printed in full - it is still valid while you read it.

Usage:
    preflight.py --code-command 'python3 totp.py --file ~/.config/totp/github.txt'
    preflight.py --code-command 'op item get GitHub --otp' --period 30
    preflight.py --code-command '...' --skip-clock       # offline

Exit codes: 0 ok, 2 usage, 3 command failed, 4 clock drift, 5 output not code-shaped,
6 non-deterministic output, 7 too slow.
"""

from __future__ import annotations

import argparse
import email.utils
import re
import shlex
import subprocess
import sys
import time
import urllib.request

CODE_RE = re.compile(r"^[0-9]{6,10}$|^[23456789BCDFGHJKMNPQRTVWXY]{5}$")
# A code command MUST be idempotent: this script runs it twice, and a login retry runs
# it again. A backup-code source consumes one single-use code per call, so preflighting
# one destroys two codes and then fails anyway (two pops are never equal).
DESTRUCTIVE_RE = re.compile(r"(^|\s)--pop(\s|$)|\bconsume\b|\bburn\b")


def die(msg: str, code: int) -> None:
    print(f"preflight: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


def mask(code: str) -> str:
    return f"{code[0]}{'*' * (len(code) - 2)}{code[-1]}" if len(code) > 2 else "*" * len(code)


def fetch(command: str, timeout: int) -> tuple[str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        die(
            f"code command did not finish within {timeout}s — it is probably waiting for an "
            "interactive unlock, which never completes in an automated run",
            3,
        )
    except (FileNotFoundError, ValueError) as exc:
        die(f"cannot run code command: {exc}", 3)
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        die(f"code command exited {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}", 3)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        die("code command printed nothing on stdout", 5)
    # The contract is stdout == the code, nothing else. Vendor CLIs chatter (bw sync
    # notices, op deprecation banners, PowerShell profile output), and a consumer
    # doing `$(cmd)` would submit the banner. Catch it here, off-site, rather than
    # at the login form where it costs an attempt.
    codes = [line for line in lines if CODE_RE.match(line)]
    if len(lines) == 1 and not codes:
        die(
            f"output is not code-shaped: {lines[0][:40]!r}. Expected 6-10 digits (or a "
            "5-character Steam code). A long base32 string means the SEED was fetched "
            "instead of a code — 1Password needs '?attribute=otp'.",
            5,
        )
    if len(lines) > 1 or len(codes) != 1:
        die(
            f"stdout must contain the code and nothing else; got {len(lines)} line(s): "
            f"{' / '.join(lines)[:120]!r}. Route diagnostics to stderr, or wrap the "
            "command so only the code reaches stdout.",
            5,
        )
    return codes[0], elapsed


def check_clock(period: int) -> None:
    request = urllib.request.Request(
        "https://www.cloudflare.com", method="HEAD", headers={"User-Agent": "totp-preflight"}
    )
    before = time.time()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed http(s) endpoint, not a caller-supplied scheme
            header = response.headers.get("Date")
    except OSError as exc:
        print(f"preflight: WARN: clock check skipped, network unreachable ({exc})", file=sys.stderr)
        return
    after = time.time()
    if not header:
        print("preflight: WARN: clock check skipped, no Date header", file=sys.stderr)
        return
    offset = (before + after) / 2 - email.utils.parsedate_to_datetime(header).timestamp()
    if abs(offset) > period / 3:
        die(
            f"host clock is {offset:+.1f}s off network time — every code will be rejected. "
            "Sync the clock (macOS: `sudo sntp -sS time.apple.com`; Linux: "
            "`sudo chronyc makestep`) before attempting the login",
            4,
        )
    print(f"  clock       {offset:+.1f}s vs network time (ok)")


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--code-command",
        required=True,
        help="shell command that prints one code to stdout and exits 0",
    )
    p.add_argument("--period", type=int, default=30, help="TOTP window in seconds (default 30)")
    p.add_argument("--timeout", type=int, default=20, help="per-invocation timeout (default 20s)")
    p.add_argument("--skip-clock", action="store_true", help="do not check network time")
    args = p.parse_args()

    if args.period <= 0:
        die(f"--period must be positive, got {args.period}", 2)

    if DESTRUCTIVE_RE.search(args.code_command):
        die(
            "that command consumes a single-use code each time it runs, so it is not a "
            "code command. Preflight runs the command twice and a retry runs it again — "
            "checking it would destroy several backup codes and still fail, because two "
            "backup codes are never equal. Backup codes are a deliberate one-shot "
            "fallback a human chooses, not an automated code source: preflight the TOTP "
            "source instead.",
            2,
        )

    # Start inside a fresh window so the two probes cannot straddle a boundary and
    # report a false "non-deterministic" failure.
    remaining = args.period - (time.time() % args.period)
    if remaining < min(5, args.period / 2):
        time.sleep(remaining + 0.1)

    first, elapsed = fetch(args.code_command, args.timeout)
    residual = args.period - (time.time() % args.period)
    print(f"  command     ok, returned {len(first)}-char code {mask(first)} in {elapsed:.2f}s")
    # Latency is not the same as residual validity: a fast command can still hand back
    # a code with half a second left. Providers that compute the code remotely cannot
    # sleep for you, so the caller must ask for a fresh window.
    if residual < 5:
        print(
            f"  WARNING: that code had {residual:.1f}s left. Pass --min-validity 5 to the "
            "code command so a dying code is never handed to a form.",
            file=sys.stderr,
        )

    # Compare only if both probes landed in the SAME time step; a window that rolls
    # between them legitimately yields two different codes.
    step_first = int(time.time() // args.period)
    second, _ = fetch(args.code_command, args.timeout)
    step_second = int(time.time() // args.period)
    if step_first != step_second:
        print("  determinism skipped (the window rolled between probes)")
    elif second != first:
        die(
            "two runs inside one time step returned different codes — the command is not a "
            "deterministic TOTP source",
            6,
        )
    else:
        print("  determinism ok, stable within one window")

    budget = args.period / 3
    if elapsed > budget:
        die(
            f"code command takes {elapsed:.1f}s, over the {budget:.0f}s budget for a "
            f"{args.period}s window — the code can expire before the form is submitted",
            7,
        )
    print(f"  latency     {elapsed:.2f}s of a {args.period}s window (ok)")

    if not args.skip_clock:
        check_clock(args.period)

    print("preflight: OK — safe to attempt the login")
    return 0


if __name__ == "__main__":
    sys.exit(main())
