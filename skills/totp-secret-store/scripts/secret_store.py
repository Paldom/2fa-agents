#!/usr/bin/env python3
"""Store and retrieve 2FA secrets and backup codes in the OS keychain.

Secrets always move over stdin/stdout, never over argv: command-line arguments are
world-readable via `ps` and land in shell history.

Backends, auto-detected in this order:
  macos     `security`      (macOS login keychain)
  libsecret `secret-tool`   (GNOME Keyring / KWallet via libsecret)
  windows   PowerShell Microsoft.PowerShell.SecretStore
  file      ~/.config/totp/<service>/<account>  (mode 600) - fallback

Usage:
    printf '%s' "$SEED" | secret_store.py set github
    secret_store.py get github | totp.py --stdin    # get belongs on the LEFT of a pipe
    secret_store.py describe github                 # inspect it WITHOUT revealing it
    secret_store.py get github --service totp-backup --pop   # burn one backup code
    secret_store.py list
    secret_store.py delete github
    secret_store.py backends                        # which backend and why
    secret_store.py selftest                        # value round-tripping

Never run `get` on its own to "see what is stored" — that puts the seed on stdout and
into whatever captured it. Use `describe`. A leaked seed is permanent; a leaked code
lasts 30 seconds.

Exit codes: 0 ok, 2 usage error, 3 not found, 4 backend failure.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

DEFAULT_SERVICE = "totp"
FILE_ROOT = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "totp"


def die(msg: str, code: int = 2) -> None:
    print(f"secret-store: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def run(cmd: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)


SEPARATOR = "|"


def normalize(raw: str) -> str:
    """Collapse a multi-line value to one line, preserving each line exactly.

    macOS `security -w` reads the secret from an interactive *line* prompt, so a
    multi-line value silently fails ("passwords don't match"). Lines are joined with
    `|` rather than a space because some issuers print backup codes WITH internal
    spaces ("1234 5678"); splitting on whitespace would turn one code into two.
    `|` appears in no base32 seed, otpauth URI, or recovery code.

    A single-line value is stored verbatim, so the documented shell pipe
    `security find-generic-password -w ... | totp.py --stdin` still works.
    """
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) == 1:
        return lines[0]
    if any(SEPARATOR in line for line in lines):
        die(f"a value line contains {SEPARATOR!r}, which is used as the list separator")
    return SEPARATOR.join(lines)


def split_values(stored: str) -> list[str]:
    return [v.strip() for v in stored.split(SEPARATOR) if v.strip()]


def detect_backend() -> str:
    if sys.platform == "darwin" and shutil.which("security"):
        return "macos"
    if shutil.which("secret-tool"):
        return "libsecret"
    if sys.platform == "win32" and shutil.which("powershell"):
        return "windows"
    return "file"


# --- macOS -------------------------------------------------------------------
# `security add-generic-password -w` with no value prompts for the secret twice.
# Feeding it twice on stdin is the only non-interactive path that keeps the secret
# out of argv.


def macos_set(service: str, account: str, secret: str) -> None:
    proc = run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-l",
            f"{service}: {account}",
            "-w",
        ],
        stdin=f"{secret}\n{secret}\n",
    )
    if proc.returncode != 0:
        die(f"keychain write failed: {proc.stderr.strip()}", 4)


def macos_get(service: str, account: str) -> str:
    proc = run(["security", "find-generic-password", "-w", "-a", account, "-s", service])
    if proc.returncode != 0:
        die(f"no entry for account {account!r} in service {service!r}", 3)
    return proc.stdout.rstrip("\n")


def macos_list(service: str) -> list[str]:
    # dump-keychain prints attributes in alphabetical order, so "acct" arrives
    # BEFORE "svce" — the pair must be read per record, not streamed.
    proc = run(["security", "dump-keychain"])
    accounts = []
    for record in proc.stdout.split("keychain: "):
        attrs = {}
        for line in record.splitlines():
            line = line.strip()
            for key in ('"acct"<blob>=', '"svce"<blob>='):
                if line.startswith(key):
                    attrs[key[1:5]] = line.split("=", 1)[1].strip('"')
        if attrs.get("svce") == service and attrs.get("acct"):
            accounts.append(attrs["acct"])
    return sorted(set(accounts))


def macos_delete(service: str, account: str) -> None:
    proc = run(["security", "delete-generic-password", "-a", account, "-s", service])
    if proc.returncode != 0:
        die(f"no entry for account {account!r} in service {service!r}", 3)


# --- libsecret ---------------------------------------------------------------


def libsecret_set(service: str, account: str, secret: str) -> None:
    proc = run(
        [
            "secret-tool",
            "store",
            "--label",
            f"{service}: {account}",
            "service",
            service,
            "account",
            account,
        ],
        stdin=secret,
    )
    if proc.returncode != 0:
        die(f"secret-tool store failed: {proc.stderr.strip()}", 4)


def libsecret_get(service: str, account: str) -> str:
    proc = run(["secret-tool", "lookup", "service", service, "account", account])
    if proc.returncode != 0 or not proc.stdout:
        die(f"no entry for account {account!r} in service {service!r}", 3)
    return proc.stdout.rstrip("\n")


def libsecret_list(service: str) -> list[str]:
    proc = run(["secret-tool", "search", "--all", "service", service])
    return sorted(
        {
            line.split("=", 1)[1].strip()
            for line in proc.stderr.splitlines() + proc.stdout.splitlines()
            if line.strip().startswith("attribute.account =")
        }
    )


def libsecret_delete(service: str, account: str) -> None:
    proc = run(["secret-tool", "clear", "service", service, "account", account])
    if proc.returncode != 0:
        die(f"secret-tool clear failed: {proc.stderr.strip()}", 4)


# --- Windows -----------------------------------------------------------------
# Secrets are passed to PowerShell over stdin, never interpolated into the script.

PS_SET = (
    "$s = [Console]::In.ReadToEnd();"
    "Set-Secret -Name $env:SS_NAME -Secret $s -Vault $env:SS_VAULT -ErrorAction Stop"
)
PS_GET = "Get-Secret -Name $env:SS_NAME -Vault $env:SS_VAULT -AsPlainText -ErrorAction Stop"
PS_LIST = "Get-SecretInfo -Vault $env:SS_VAULT | ForEach-Object { $_.Name }"
PS_DELETE = "Remove-Secret -Name $env:SS_NAME -Vault $env:SS_VAULT -ErrorAction Stop"


def windows_run(script: str, service: str, account: str = "", stdin: str | None = None) -> str:
    env = {**os.environ, "SS_VAULT": service, "SS_NAME": account}
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        die(
            f"PowerShell SecretManagement failed: {proc.stderr.strip()}\n"
            "Install once with: Install-Module Microsoft.PowerShell.SecretManagement, "
            "Microsoft.PowerShell.SecretStore",
            4,
        )
    return proc.stdout.rstrip("\n")


# --- file fallback -----------------------------------------------------------


def file_path(service: str, account: str) -> Path:
    return FILE_ROOT / service / account


def file_set(service: str, account: str, secret: str) -> None:
    path = file_path(service, account)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Write to a sibling temp file and rename over the target: an interrupted write
    # must never truncate a stored backup-code list. Create with 600 from the start,
    # since writing then chmod leaves a world-readable window.
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(secret)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)  # atomic on POSIX and Windows
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def file_get(service: str, account: str) -> str:
    path = file_path(service, account)
    if not path.is_file():
        die(f"no entry at {path}", 3)
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        print(f"secret-store: warning: {path} is mode {mode:o}, should be 600", file=sys.stderr)
    return path.read_text(encoding="utf-8").rstrip("\n")


def file_list(service: str) -> list[str]:
    directory = FILE_ROOT / service
    return sorted(p.name for p in directory.iterdir() if p.is_file()) if directory.is_dir() else []


def file_delete(service: str, account: str) -> None:
    path = file_path(service, account)
    if not path.is_file():
        die(f"no entry at {path}", 3)
    path.unlink()


# --- dispatch ----------------------------------------------------------------


def store_set(backend: str, service: str, account: str, secret: str) -> None:
    if backend == "windows":
        windows_run(PS_SET, service, account, secret)
        return
    {"macos": macos_set, "libsecret": libsecret_set, "file": file_set}[backend](
        service, account, secret
    )


def store_get(backend: str, service: str, account: str) -> str:
    if backend == "windows":
        return windows_run(PS_GET, service, account)
    return {"macos": macos_get, "libsecret": libsecret_get, "file": file_get}[backend](
        service, account
    )


def store_list(backend: str, service: str) -> list[str]:
    if backend == "windows":
        return [n for n in windows_run(PS_LIST, service).splitlines() if n]
    return {"macos": macos_list, "libsecret": libsecret_list, "file": file_list}[backend](service)


def store_delete(backend: str, service: str, account: str) -> None:
    if backend == "windows":
        windows_run(PS_DELETE, service, account)
        return
    {"macos": macos_delete, "libsecret": libsecret_delete, "file": file_delete}[backend](
        service, account
    )


def describe(stored: str) -> str:
    """Summarise a stored value WITHOUT revealing it.

    `get` exists to be the left side of a pipe. Running it alone — to check what is
    stored, or to debug a failing pipeline stage — puts the seed on stdout and from
    there into an agent transcript, where it is a permanent compromise rather than a
    30-second one. This gives the same reassurance with nothing sensitive in it.
    """
    values = split_values(stored)
    if len(values) > 1:
        return f"list of {len(values)} value(s) (backup codes); first is {len(values[0])} chars"
    value = values[0] if values else ""
    if value.lower().startswith("otpauth"):
        parts = urllib.parse.urlsplit(value)
        query = urllib.parse.parse_qs(parts.query)
        get = lambda k, d: (query.get(k) or [d])[0]  # noqa: E731
        secret = get("secret", "")
        return (
            f"otpauth {parts.netloc} URI; label={urllib.parse.unquote(parts.path.lstrip('/'))!r} "
            f"issuer={get('issuer', '')!r} digits={get('digits', '6')} "
            f"period={get('period', '30')} algorithm={get('algorithm', 'SHA1')} "
            f"secret={len(secret)} base32 chars"
        )
    return (
        f"bare secret, {len(value)} chars, {'valid' if _is_base32(value) else 'NOT valid'} base32"
    )


def _is_base32(value: str) -> bool:
    cleaned = "".join(value.split()).replace("-", "").rstrip("=").upper()
    return bool(cleaned) and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in cleaned)


def selftest() -> int:
    """Round-trip the value normalisation. This is where silent corruption lives."""
    cases = [
        # (input, stored, values-after-split)
        ("JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP", ["JBSWY3DPEHPK3PXP"]),
        (
            "otpauth://totp/A:b?secret=JBSW",
            "otpauth://totp/A:b?secret=JBSW",
            ["otpauth://totp/A:b?secret=JBSW"],
        ),
        ("  spaced-seed  \n", "spaced-seed", ["spaced-seed"]),
        # Backup codes printed WITH internal spaces must stay ONE code each.
        ("1234 5678\nabcd efgh\n", "1234 5678|abcd efgh", ["1234 5678", "abcd efgh"]),
        ("aa\n\n\nbb\n", "aa|bb", ["aa", "bb"]),
    ]
    failures = 0
    for raw, want_stored, want_values in cases:
        got_stored = normalize(raw)
        got_values = split_values(got_stored)
        if got_stored != want_stored or got_values != want_values:
            failures += 1
            print(
                f"FAIL {raw!r}: stored={got_stored!r} (want {want_stored!r}), "
                f"values={got_values} (want {want_values})",
                file=sys.stderr,
            )
    # A single-line value must survive verbatim, or the documented
    # `... | totp.py --stdin` pipe breaks.
    if normalize("JBSWY3DPEHPK3PXP") != "JBSWY3DPEHPK3PXP":
        failures += 1
        print("FAIL single-line value was altered", file=sys.stderr)
    if failures:
        print(f"selftest: {failures} failure(s)", file=sys.stderr)
        return 3
    print(f"selftest: OK ({len(cases) + 1} checks)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "action", choices=("set", "get", "describe", "list", "delete", "backends", "selftest")
    )
    p.add_argument("account", nargs="?", help="account name, e.g. github")
    p.add_argument(
        "--service",
        default=DEFAULT_SERVICE,
        help=f"namespace within the keychain (default: {DEFAULT_SERVICE}; "
        "use totp-backup for recovery codes)",
    )
    p.add_argument(
        "--backend",
        choices=("macos", "libsecret", "windows", "file"),
        help="force a backend instead of auto-detecting",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="get: allow printing a secret to a terminal (it will be in scrollback)",
    )
    p.add_argument(
        "--pop",
        action="store_true",
        help="get: print the first line and write the rest back (burns one backup code)",
    )
    args = p.parse_args()

    if args.action == "selftest":
        return selftest()

    backend = args.backend or detect_backend()

    if args.action == "backends":
        print(f"selected: {backend}")
        for name, available in (
            ("macos", sys.platform == "darwin" and bool(shutil.which("security"))),
            ("libsecret", bool(shutil.which("secret-tool"))),
            ("windows", sys.platform == "win32" and bool(shutil.which("powershell"))),
            ("file", True),
        ):
            print(
                f"  {name:<10} {'available' if available else 'unavailable'}"
                f"{'   <- ' + str(FILE_ROOT) if name == 'file' else ''}"
            )
        return 0

    if args.action == "list":
        for account in store_list(backend, args.service):
            print(account)
        return 0

    if not args.account:
        die(f"{args.action} needs an account name")

    if args.action == "set":
        if sys.stdin.isatty():
            die(
                "refusing to read a secret from a terminal; pipe it in: "
                f"printf '%s' \"$SEED\" | {Path(sys.argv[0]).name} set {args.account}"
            )
        secret = normalize(sys.stdin.read())
        if not secret:
            die("stdin was empty")
        store_set(backend, args.service, args.account, secret)
        print(f"stored {args.account!r} in {args.service!r} ({backend})", file=sys.stderr)
        return 0

    if args.action == "describe":
        print(describe(store_get(backend, args.service, args.account)))
        return 0

    if args.action == "get":
        value = store_get(backend, args.service, args.account)
        if sys.stdout.isatty() and not args.pop and not args.force:
            die(
                "refusing to print a secret to a terminal. Use it on the left of a pipe "
                f"(`... get {args.account} | totp.py --stdin`), run `describe {args.account}` "
                "to inspect it safely, or pass --force if you really mean it."
            )
        if not args.pop:
            # A list prints one per line; a single value prints verbatim so it can be
            # piped straight into a generator.
            print("\n".join(split_values(value)) if SEPARATOR in value else value)
            return 0
        codes = split_values(value)
        if not codes:
            die(f"{args.account!r} in {args.service!r} has no remaining codes", 3)
        used, rest = codes[0], codes[1:]
        # Write the remainder back BEFORE printing, so a crash can never hand out a
        # code that is still stored: better to lose one than to reuse one. The file
        # backend's write is atomic, so the remaining codes survive an interruption.
        if rest:
            store_set(backend, args.service, args.account, SEPARATOR.join(rest))
        else:
            store_delete(backend, args.service, args.account)
        print(used)
        print(f"{len(rest)} code(s) left in {args.service}/{args.account}", file=sys.stderr)
        return 0

    store_delete(backend, args.service, args.account)
    print(f"deleted {args.account!r} from {args.service!r}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
