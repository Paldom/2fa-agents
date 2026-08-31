#!/usr/bin/env python3
"""Fetch a TOTP code from a managed provider. Standard library only.

Wraps 1Password, Bitwarden, HashiCorp Vault and 2FAuth behind one contract:
print exactly one code to stdout and exit 0, or exit non-zero with an actionable
message on stderr. Nothing ever blocks on a prompt.

The reason this exists rather than calling the vendor CLI directly: `op` and `bw`
fall back to an *interactive* prompt when their credential is missing, so an
unattended agent hangs forever instead of failing. Every path here checks its
credential first and runs under a hard timeout.

Usage:
    fetch_code.py check                                  # providers + auth status
    fetch_code.py 1password "GitHub" [--vault Automation] [--field "one-time password"]
    fetch_code.py bitwarden <item-id>
    fetch_code.py vault <key> [--addr https://vault:8200] [--mount totp]
    fetch_code.py 2fauth <account-id> [--url https://2fauth.example.com]

Exit codes: 0 ok, 2 usage, 3 not found or ambiguous, 5 credential missing/expired,
6 timeout, 7 provider error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 30
CODE_RE = re.compile(r"^[0-9]{6,10}$|^[23456789BCDFGHJKMNPQRTVWXY]{5}$")


def die(msg: str, code: int) -> None:
    print(f"fetch-code: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def run(cmd: list[str], env_extra: dict | None = None) -> str:
    """Run a CLI with stdin closed so it can never wait on a prompt."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            stdin=subprocess.DEVNULL,
            env={**os.environ, **(env_extra or {})},
        )
    except subprocess.TimeoutExpired:
        die(
            f"{cmd[0]} did not answer within {TIMEOUT}s — it is most likely waiting for "
            "an interactive unlock; provide the credential in the environment instead",
            6,
        )
    except FileNotFoundError:
        die(f"{cmd[0]} is not installed or not on PATH", 5)
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or proc.stdout.strip()
        low = stderr.lower()
        if "more than one" in low or "multiple" in low:
            die(f"{stderr}\nThe search term matched several items — use the exact item ID", 3)
        if "not found" in low or "no item" in low or "isn't an item" in low:
            die(stderr, 3)
        if any(
            t in low
            for t in (
                "not logged in",
                "unauthor",
                "locked",
                "session",
                "token",
                "sign in",
                "signin",
                "authenticate",
            )
        ):
            die(f"{stderr}\nCredential missing or expired — see `fetch_code.py check`", 5)
        die(stderr, 7)
    return proc.stdout.strip()


def http_json(url: str, headers: dict, method: str = "GET") -> dict:
    request = urllib.request.Request(url, headers=headers, method=method)  # noqa: S310 - fixed http(s) endpoint, not a caller-supplied scheme
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 - fixed http(s) endpoint, not a caller-supplied scheme
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        if exc.code in (401, 403):
            die(f"HTTP {exc.code} from {url}: token rejected or lacks permission. {body}", 5)
        if exc.code == 404:
            die(f"HTTP 404 from {url}: no such key/account. {body}", 3)
        die(f"HTTP {exc.code} from {url}: {body}", 7)
    except (urllib.error.URLError, TimeoutError) as exc:
        die(f"cannot reach {url}: {exc}", 6)
    except json.JSONDecodeError:
        die(f"{url} did not return JSON — check the base URL points at the API, not the web UI", 7)


# --- providers ---------------------------------------------------------------


def onepassword(args: argparse.Namespace) -> str:
    # `op` prompts for biometric/desktop unlock when no service-account token is set.
    if not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN") and not os.environ.get("OP_CONNECT_TOKEN"):
        die(
            "OP_SERVICE_ACCOUNT_TOKEN is not set. Without it `op` waits for an interactive "
            "unlock and an unattended run hangs. Create a service account, grant it the "
            "vault, and export the token.",
            5,
        )
    cmd = ["op", "item", "get", args.item, "--otp"]
    if args.vault:
        cmd += ["--vault", args.vault]
    # --otp cannot be combined with --fields; the CLI errors out if you try.
    return run(cmd)


def bitwarden(args: argparse.Namespace) -> str:
    if not os.environ.get("BW_SESSION"):
        die(
            "BW_SESSION is not set. Unlock once and export it: "
            "export BW_SESSION=$(bw unlock --raw)",
            5,
        )
    return run(["bw", "get", "totp", args.item, "--nointeraction"])


def vault(args: argparse.Namespace) -> str:
    token = os.environ.get("VAULT_TOKEN")
    addr = args.addr or os.environ.get("VAULT_ADDR")
    if not token:
        die("VAULT_TOKEN is not set", 5)
    if not addr:
        die("no Vault address: pass --addr or set VAULT_ADDR", 2)
    data = http_json(
        f"{addr.rstrip('/')}/v1/{args.mount.strip('/')}/code/{args.key}", {"X-Vault-Token": token}
    )
    code = (data.get("data") or {}).get("code")
    if not code:
        die(f"Vault response had no data.code field: {json.dumps(data)[:200]}", 7)
    return code


def twofauth(args: argparse.Namespace) -> str:
    token = os.environ.get("TWOFAUTH_TOKEN")
    url = args.url or os.environ.get("TWOFAUTH_URL")
    if not token:
        die("TWOFAUTH_TOKEN is not set (2FAuth Settings > OAUTH > generate a token)", 5)
    if not url:
        die("no 2FAuth base URL: pass --url or set TWOFAUTH_URL", 2)
    data = http_json(
        f"{url.rstrip('/')}/api/v1/twofaccounts/{args.account}/otp",
        {"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    code = data.get("password") or data.get("otp")
    if not code:
        die(f"2FAuth response had no password field: {json.dumps(data)[:200]}", 7)
    return code


def check() -> int:
    rows = [
        ("1password", "op", "OP_SERVICE_ACCOUNT_TOKEN"),
        ("bitwarden", "bw", "BW_SESSION"),
        ("vault", None, "VAULT_TOKEN"),
        ("2fauth", None, "TWOFAUTH_TOKEN"),
    ]
    usable = 0
    for name, binary, variable in rows:
        installed = "n/a" if binary is None else ("yes" if shutil.which(binary) else "NO")
        has_credential = "yes" if os.environ.get(variable) else "NO"
        ready = installed != "NO" and has_credential == "yes"
        usable += ready
        print(
            f"{name:<12} cli={installed:<4} {variable}={has_credential:<4} "
            f"{'ready' if ready else 'not usable'}"
        )
    if not usable:
        sys.stdout.flush()  # keep the table above the diagnosis when streams are merged
        print(
            "\nNo provider is usable. Each needs its credential in the environment; "
            "without one the vendor CLIs wait for an interactive unlock.",
            file=sys.stderr,
        )
        return 5
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="provider", required=True)
    sub.add_parser("check", help="show which providers are installed and credentialed")

    op_parser = sub.add_parser("1password")
    op_parser.add_argument("item", help="item name or ID (an ID avoids ambiguous matches)")
    op_parser.add_argument("--vault", help="required when the service account sees several vaults")

    bw_parser = sub.add_parser("bitwarden")
    bw_parser.add_argument("item", help="item ID (a name that matches twice is an error)")

    vault_parser = sub.add_parser("vault")
    vault_parser.add_argument("key", help="key name in the TOTP secrets engine")
    vault_parser.add_argument("--addr", help="Vault address (default: $VAULT_ADDR)")
    vault_parser.add_argument("--mount", default="totp", help="engine mount path (default: totp)")

    fa_parser = sub.add_parser("2fauth")
    fa_parser.add_argument("account", help="numeric twofaccount id")
    fa_parser.add_argument("--url", help="2FAuth base URL (default: $TWOFAUTH_URL)")

    for sub_parser in (op_parser, bw_parser, vault_parser, fa_parser):
        sub_parser.add_argument(
            "--min-validity",
            type=int,
            default=0,
            metavar="SECS",
            help="wait for a window with at least SECS left before fetching",
        )
        sub_parser.add_argument(
            "--period",
            type=int,
            default=30,
            help="the account's TOTP window in seconds (default 30)",
        )

    args = p.parse_args()
    if args.provider == "check":
        return check()

    # TOTP windows are absolute (floor(unix_time / period)), identical for every
    # party, so residual validity is computable from the local clock even though the
    # provider computed the code. Wait BEFORE fetching: a remote fetch adds a round
    # trip on top, and a code that arrives with 0.5s left is rejected in a way that
    # looks exactly like a wrong seed.
    if args.min_validity:
        if args.min_validity >= args.period:
            die(
                f"--min-validity {args.min_validity} >= period {args.period}: "
                "no window is ever that fresh",
                2,
            )
        remaining = args.period - (time.time() % args.period)
        if remaining < args.min_validity:
            time.sleep(remaining + 0.05)

    raw = {"1password": onepassword, "bitwarden": bitwarden, "vault": vault, "2fauth": twofauth}[
        args.provider
    ](args)

    # Vendor CLIs chatter on stdout: bw sync notices, op deprecation banners, a
    # PowerShell profile banner. Never blindly take the first line — pick the single
    # code-shaped one, and refuse when that is ambiguous.
    candidates = [line.strip() for line in (raw or "").splitlines() if CODE_RE.match(line.strip())]
    if not candidates:
        preview = " / ".join((raw or "").splitlines()[:3])[:120] or "(empty)"
        die(
            f"no code-shaped line in the provider's stdout: {preview!r}. A long base32 "
            "string means the SEED was fetched instead of a code (1Password needs "
            "?attribute=otp).",
            7,
        )
    if len(candidates) > 1:
        die(
            f"{len(candidates)} code-shaped lines in stdout — cannot tell which is the "
            "code; the provider is printing extra output",
            7,
        )
    print(candidates[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
