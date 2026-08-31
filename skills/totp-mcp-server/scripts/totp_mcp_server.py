#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=2.1,<3"]
# ///
"""Self-hosted MCP server that hands out TOTP codes without exposing the seed.

Two tools, deliberately read-only:
    list_totp_accounts()        -> which accounts this server can serve
    get_totp_code(account)      -> the current code + seconds of validity

There is intentionally NO tool that stores, reads, or exports a secret. Enrolment
is a human action; a write tool would be a privilege-escalation surface reachable
by prompt injection through any content the model reads.

Configure with environment variables (set them in the MCP client config):
    TOTP_MCP_BACKEND    keychain | file        (default: keychain on macOS/Linux
                                                with a secret tool, else file)
    TOTP_MCP_SERVICE    keychain service name  (default: totp)
    TOTP_MCP_DIR        file backend directory (default: ~/.config/totp/totp)
    TOTP_MCP_ACCOUNTS   comma-separated allowlist; empty = every stored account
    TOTP_MCP_AUDIT      audit log path         (default: ~/.local/state/totp-mcp/audit.log)
    TOTP_MCP_RATE       max calls per account per minute (default: 10)

Run directly (`uv run --script totp_mcp_server.py`) or register it as a stdio
server. Everything diagnostic goes to stderr: anything written to stdout that is
not an MCP message corrupts the protocol stream and the server dies silently.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
from collections import deque
from pathlib import Path

from mcp.server import MCPServer

# The SDK's ToolError is the *only* exception whose message reaches the model. Any
# other exception is treated as a crash: the client gets "Error executing tool X"
# and every recovery hint you wrote is dropped into a stderr traceback.
from mcp.server.mcpserver.exceptions import ToolError

SERVICE = os.environ.get("TOTP_MCP_SERVICE", "totp")
SECRET_DIR = Path(os.environ.get("TOTP_MCP_DIR", Path.home() / ".config" / "totp" / SERVICE))
ALLOWLIST = {a.strip() for a in os.environ.get("TOTP_MCP_ACCOUNTS", "").split(",") if a.strip()}
AUDIT_PATH = Path(
    os.environ.get("TOTP_MCP_AUDIT", Path.home() / ".local" / "state" / "totp-mcp" / "audit.log")
)
RATE_PER_MINUTE = int(os.environ.get("TOTP_MCP_RATE", "10"))
ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"

_calls: dict[str, deque[float]] = {}


def backend() -> str:
    configured = os.environ.get("TOTP_MCP_BACKEND")
    if configured:
        return configured
    if sys.platform == "darwin" and shutil.which("security"):
        return "keychain"
    if shutil.which("secret-tool"):
        return "keychain"
    return "file"


def audit(event: str, account: str, detail: str = "") -> None:
    """Append-only record of every request. Never records the code or the seed."""
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(AUDIT_PATH, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "event": event,
                        "account": account,
                        "detail": detail,
                    }
                )
                + "\n"
            )
    except OSError as exc:
        print(f"totp-mcp: audit write failed: {exc}", file=sys.stderr)


def rate_limit(account: str) -> None:
    now = time.time()
    window = _calls.setdefault(account, deque())
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= RATE_PER_MINUTE:
        audit("rate_limited", account)
        raise ToolError(
            f"rate limit reached for {account} ({RATE_PER_MINUTE}/minute). A code is only "
            "valid for one 30-second window, so repeated requests cannot help; wait for the "
            "next window instead of retrying."
        )
    window.append(now)


def stored_accounts() -> list[str]:
    if backend() == "file":
        names = (
            sorted(p.name for p in SECRET_DIR.iterdir() if p.is_file())
            if SECRET_DIR.is_dir()
            else []
        )
    elif sys.platform == "darwin":
        proc = subprocess.run(["security", "dump-keychain"], capture_output=True, text=True)
        names = []
        for record in proc.stdout.split("keychain: "):
            attrs = {}
            for line in record.splitlines():
                line = line.strip()
                for key in ('"acct"<blob>=', '"svce"<blob>='):
                    if line.startswith(key):
                        attrs[key[1:5]] = line.split("=", 1)[1].strip('"')
            if attrs.get("svce") == SERVICE and attrs.get("acct"):
                names.append(attrs["acct"])
        names = sorted(set(names))
    else:
        proc = subprocess.run(
            ["secret-tool", "search", "--all", "service", SERVICE], capture_output=True, text=True
        )
        names = sorted(
            {
                line.split("=", 1)[1].strip()
                for line in (proc.stdout + proc.stderr).splitlines()
                if line.strip().startswith("attribute.account =")
            }
        )
    return [n for n in names if not ALLOWLIST or n in ALLOWLIST]


def load_secret(account: str) -> str:
    """Read one secret. Callers must have passed `account` through stored_accounts()."""
    if backend() == "file":
        path = SECRET_DIR / account
        if not path.is_file():
            raise ToolError(f"no stored secret for {account!r}")
        return path.read_text(encoding="utf-8").strip()
    if sys.platform == "darwin":
        proc = subprocess.run(
            ["security", "find-generic-password", "-w", "-a", account, "-s", SERVICE],
            capture_output=True,
            text=True,
        )
    else:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", SERVICE, "account", account],
            capture_output=True,
            text=True,
        )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise ToolError(f"no stored secret for {account!r}")
    return proc.stdout.strip()


def parse(secret: str) -> dict:
    params = {
        "secret": secret,
        "digits": 6,
        "period": 30,
        "algorithm": "SHA1",
        "issuer": "",
        "encoder": "",
    }
    if not secret.lower().startswith("otpauth"):
        return params
    parts = urllib.parse.urlsplit(secret)
    if parts.netloc.lower() != "totp":
        raise ToolError("stored value is not a TOTP otpauth URI (HOTP needs a stored counter)")
    query = urllib.parse.parse_qs(parts.query)
    get = lambda k, d: (query.get(k) or [d])[0]  # noqa: E731
    if not get("secret", ""):
        raise ToolError("stored otpauth URI has no secret parameter")
    return {
        "secret": get("secret", ""),
        "digits": int(get("digits", "6")),
        "period": int(get("period", "30")),
        "algorithm": get("algorithm", "SHA1").upper().replace("-", ""),
        "issuer": get("issuer", ""),
        "encoder": get("encoder", "").lower(),
    }


def totp(params: dict, at: float) -> str:
    cleaned = "".join(params["secret"].split()).replace("-", "").rstrip("=").upper()
    try:
        key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8), casefold=True)
    except (binascii.Error, ValueError):
        raise ToolError("stored secret is not valid base32") from None
    if params["algorithm"] not in ALGORITHMS:
        raise ToolError(f"unsupported algorithm {params['algorithm']}")
    counter = int(at // params["period"])
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[params["algorithm"]]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    if params["encoder"] == "steam" or params["issuer"].lower() == "steam":
        out = ""
        for _ in range(5):
            out += STEAM_ALPHABET[value % len(STEAM_ALPHABET)]
            value //= len(STEAM_ALPHABET)
        return out
    return str(value % 10 ** params["digits"]).zfill(params["digits"])


mcp = MCPServer(
    name="totp",
    version="1.0.0",
    instructions="Provides current two-factor authentication codes for accounts the "
    "operator has enrolled on this machine. Codes are single-use and expire "
    "within seconds; request one only when a login prompt is actually asking "
    "for it, and never resubmit a code that was rejected.",
)


@mcp.tool()
def list_totp_accounts() -> list[str]:
    """List the account names this server can produce 2FA codes for."""
    accounts = stored_accounts()
    audit("list", "-", f"{len(accounts)} account(s)")
    return accounts


@mcp.tool()
def get_totp_code(account: str) -> dict:
    """Return the current TOTP code for one enrolled account.

    The code is single-use and expires when `expires_in` reaches zero. If a login
    rejects it, wait for the next window rather than sending the same digits again.
    """
    # Allowlist check before any secret access: an account name arriving from the
    # model is untrusted input, and this also blocks path traversal into the dir.
    if account not in stored_accounts():
        audit("denied", account, "not enrolled or not allowlisted")
        raise ToolError(
            f"{account!r} is not available. Call list_totp_accounts() for the exact names. "
            "Enrolling a new account is a human action and cannot be done through this server."
        )
    rate_limit(account)
    params = parse(load_secret(account))
    now = time.time()
    code = totp(params, now)
    expires_in = round(params["period"] - (now % params["period"]), 1)
    audit("issued", account, f"expires_in={expires_in}")
    return {"code": code, "expires_in": expires_in, "period": params["period"]}


if __name__ == "__main__":
    print(
        f"totp-mcp: backend={backend()} service={SERVICE} "
        f"accounts={len(stored_accounts())} audit={AUDIT_PATH}",
        file=sys.stderr,
    )
    mcp.run("stdio")
