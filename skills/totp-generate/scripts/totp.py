#!/usr/bin/env python3
"""Generate an RFC 6238 TOTP code from a shared secret. Standard library only.

The secret is a base32 string or a full otpauth:// URI. It is read from a file,
an environment variable, or stdin so it never appears in `ps` output.

Usage:
    totp.py --file ~/.config/totp/github.txt          # code on stdout, nothing else
    TOTP_SECRET=JBSW... totp.py                       # from $TOTP_SECRET
    security find-generic-password -w -s totp-github | totp.py --stdin
    totp.py --file s.txt --min-validity 5             # wait for a fresh window first
    totp.py --file s.txt --json                       # code + seconds remaining
    totp.py --selftest                                # RFC 6238 vectors

Exit codes: 0 ok, 2 usage/secret error, 3 selftest failure.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.parse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
# Steam uses a 5-character alphabet instead of decimal digits.
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


def die(msg: str, code: int = 2) -> None:
    print(f"totp: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def decode_secret(secret: str) -> bytes:
    """Base32-decode a shared secret, tolerating the formats humans paste.

    Authenticator apps display secrets in lowercase, in space- or hyphen-separated
    groups, and with RFC 4648 padding stripped. Strip separators FIRST, then pad:
    computing padding from the unstripped length is the classic silent bug.
    """
    cleaned = "".join(secret.split()).replace("-", "").rstrip("=").upper()
    if not cleaned:
        die("secret is empty")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        die(
            f"secret is not valid base32 ({len(cleaned)} chars after cleanup); "
            "check for 0/O and 1/L transcription errors"
        )
    if not key:
        die("secret decoded to zero bytes")
    return key


def parse_otpauth(uri: str) -> dict:
    """Parse an otpauth://totp/LABEL?secret=...&issuer=... URI into parameters."""
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "otpauth":
        die(f"not an otpauth:// URI (scheme {parts.scheme!r})")
    if parts.netloc.lower() == "hotp":
        die("this is a counter-based HOTP URI, not TOTP; HOTP needs a stored counter")
    if parts.netloc.lower() != "totp":
        die(f"unsupported otpauth type {parts.netloc!r} (expected 'totp')")
    q = urllib.parse.parse_qs(parts.query)
    one = lambda k, default=None: q.get(k, [default])[0]  # noqa: E731
    secret = one("secret")
    if not secret:
        die("otpauth URI has no secret= parameter")
    label = urllib.parse.unquote(parts.path.lstrip("/"))
    issuer = one("issuer") or (label.split(":", 1)[0] if ":" in label else "")
    return {
        "secret": secret,
        "label": label,
        "issuer": issuer,
        "digits": int(one("digits", "6")),
        "period": int(one("period", "30")),
        "algorithm": (one("algorithm", "SHA1") or "SHA1").upper().replace("-", ""),
        "encoder": (one("encoder", "") or "").lower(),
    }


def hotp(key: bytes, counter: int, digits: int, algorithm: str, steam: bool = False) -> str:
    """RFC 4226 dynamic truncation, shared by TOTP (counter = time step)."""
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    if steam:
        out = ""
        for _ in range(5):
            out += STEAM_ALPHABET[value % len(STEAM_ALPHABET)]
            value //= len(STEAM_ALPHABET)
        return out
    return str(value % 10**digits).zfill(digits)


def generate(
    secret: str,
    at: float,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    t0: int = 0,
    steam: bool = False,
) -> str:
    if algorithm not in ALGORITHMS:
        die(f"unsupported algorithm {algorithm!r} (SHA1, SHA256, SHA512)")
    if period <= 0:
        die(f"period must be positive, got {period}")
    if not steam and not 6 <= digits <= 10:
        die(f"digits must be 6-10, got {digits}")
    return hotp(decode_secret(secret), int((at - t0) // period), digits, algorithm, steam)


def read_secret(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read().strip()
    if args.file:
        try:
            with open(os.path.expanduser(args.file), encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            die(f"cannot read secret file: {exc}")
        # A secret file may hold comments; take the first non-comment, non-blank line.
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        die(f"secret file {args.file} has no secret line")
    if args.secret:
        return args.secret
    value = os.environ.get(args.env, "")
    if not value:
        die(f"no secret: pass it as an argument, use --file/--stdin, or set ${args.env}")
    return value


def check_clock(url: str, period: int) -> int:
    """Compare the local clock to an HTTPS server's Date header.

    Clock drift is the most common cause of "the code is always rejected", and an
    agent usually has no NTP client available to check. Accuracy is +/- ~2s
    (1-second header resolution plus round-trip), which is ample to spot the
    +/- 30s drift that breaks TOTP. The offset is reported, never applied: a host
    whose clock is wrong needs fixing, not compensating.
    """
    import email.utils
    import urllib.request

    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "totp-check-clock"})  # noqa: S310 - fixed http(s) endpoint, not a caller-supplied scheme
    before = time.time()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed http(s) endpoint, not a caller-supplied scheme
            header = response.headers.get("Date")
    except OSError as exc:
        die(f"clock check could not reach {url}: {exc}")
    after = time.time()
    if not header:
        die(f"{url} returned no Date header")
    remote = email.utils.parsedate_to_datetime(header).timestamp()
    offset = (before + after) / 2 - remote
    tolerance = period / 3
    print(
        f"local clock is {offset:+.1f}s vs {url} (tolerance +/-{tolerance:.0f}s, "
        f"round-trip {after - before:.2f}s)"
    )
    if abs(offset) > tolerance:
        print(
            f"totp: error: clock drift {offset:+.1f}s will produce rejected codes; "
            "sync the host clock (macOS: `sudo sntp -sS time.apple.com`; "
            "Linux: `sudo chronyc makestep` or enable systemd-timesyncd)",
            file=sys.stderr,
        )
        return 4
    return 0


def selftest() -> int:
    """RFC 6238 Appendix B vectors, with the Appendix A per-algorithm seeds."""
    b32 = lambda s: base64.b32encode(s).decode()  # noqa: E731
    seeds = {
        "SHA1": b32(b"12345678901234567890"),
        "SHA256": b32(b"12345678901234567890123456789012"),
        "SHA512": b32(b"1234567890123456789012345678901234567890123456789012345678901234"),
    }
    vectors = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ]
    failures = 0
    for t, *expected in vectors:
        for algorithm, want in zip(("SHA1", "SHA256", "SHA512"), expected, strict=False):
            got = generate(seeds[algorithm], t, digits=8, algorithm=algorithm)
            if got != want:
                failures += 1
                print(f"FAIL t={t} {algorithm}: want {want}, got {got}", file=sys.stderr)
    # Formatting tolerance: lowercase, spaced, unpadded base32 must decode.
    spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    if generate(spaced, 59, digits=8) != generate("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, digits=8):
        failures += 1
        print("FAIL spaced/lowercase base32 did not match canonical form", file=sys.stderr)
    if failures:
        print(f"selftest: {failures} failure(s)", file=sys.stderr)
        return 3
    print(f"selftest: OK ({len(vectors) * 3 + 1} checks)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "secret",
        nargs="?",
        help="base32 secret or otpauth:// URI (visible in `ps` — prefer --file)",
    )
    src.add_argument("--file", help="read the secret (base32 or otpauth:// URI) from this file")
    src.add_argument("--stdin", action="store_true", help="read the secret from stdin")
    p.add_argument(
        "--env",
        default="TOTP_SECRET",
        help="environment variable holding the secret (default: TOTP_SECRET)",
    )
    p.add_argument(
        "--digits", type=int, help="override digit count (default 6, or the URI's digits=)"
    )
    p.add_argument(
        "--period",
        type=int,
        help="override time step in seconds (default 30, or the URI's period=)",
    )
    p.add_argument(
        "--algorithm", help="override SHA1|SHA256|SHA512 (default SHA1, or the URI's algorithm=)"
    )
    p.add_argument(
        "--at", type=float, help="generate for this Unix timestamp instead of now (testing)"
    )
    p.add_argument(
        "--min-validity",
        type=int,
        default=0,
        metavar="SECS",
        help="if the current code expires in under SECS, wait for the next window (use before submitting a form)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=0,
        metavar="N",
        help="also print the N previous and next codes (drift diagnosis only — never submit these)",
    )
    p.add_argument(
        "--json", action="store_true", help="emit {code, expires_in, period, ...} as JSON"
    )
    p.add_argument("--selftest", action="store_true", help="run RFC 6238 test vectors and exit")
    p.add_argument(
        "--check-clock",
        nargs="?",
        const="https://www.cloudflare.com",
        metavar="URL",
        help="compare the local clock against an HTTPS Date header and exit (exit 4 on drift)",
    )
    args = p.parse_args()

    if args.selftest:
        return selftest()
    if args.check_clock:
        return check_clock(args.check_clock, args.period or 30)

    raw = read_secret(args)
    params = {
        "secret": raw,
        "label": "",
        "issuer": "",
        "digits": 6,
        "period": 30,
        "algorithm": "SHA1",
        "encoder": "",
    }
    if raw.lower().startswith("otpauth"):
        params = parse_otpauth(raw)
    for key in ("digits", "period", "algorithm"):
        if getattr(args, key) is not None:
            params[key] = getattr(args, key)
    params["algorithm"] = str(params["algorithm"]).upper().replace("-", "")
    steam = params["encoder"] == "steam" or params["issuer"].lower() == "steam"

    now = args.at if args.at is not None else time.time()
    period = params["period"]
    expires_in = period - (now % period)
    if args.min_validity and args.at is None and expires_in < args.min_validity:
        if args.min_validity >= period:
            die(
                f"--min-validity {args.min_validity} >= period {period}: no window is ever that fresh"
            )
        time.sleep(expires_in + 0.05)
        now = time.time()
        expires_in = period - (now % period)

    code = generate(
        params["secret"], now, params["digits"], period, params["algorithm"], steam=steam
    )

    if args.json:
        out = {
            "code": code,
            "expires_in": round(expires_in, 1),
            "period": period,
            "digits": params["digits"],
            "algorithm": params["algorithm"],
        }
        if params["issuer"]:
            out["issuer"] = params["issuer"]
        if params["label"]:
            out["label"] = params["label"]
        if args.window:
            out["window"] = [
                generate(
                    params["secret"],
                    now + i * period,
                    params["digits"],
                    period,
                    params["algorithm"],
                    steam=steam,
                )
                for i in range(-args.window, args.window + 1)
            ]
        print(json.dumps(out))
    elif args.window:
        for i in range(-args.window, args.window + 1):
            offset = generate(
                params["secret"],
                now + i * period,
                params["digits"],
                period,
                params["algorithm"],
                steam=steam,
            )
            print(f"{i:+d} {offset}" if i else f" 0 {offset}  <- current, {expires_in:.0f}s left")
    else:
        print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
