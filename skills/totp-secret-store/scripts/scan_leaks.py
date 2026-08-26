#!/usr/bin/env python3
"""Find 2FA secrets exposed in a repository, and prove the secret dir is really ignored.

`.gitignore` does NOT apply to files git already tracks. A path added before the
ignore rule stays tracked, keeps getting committed, and `git check-ignore` still
reports it as ignored — the most common way a seed reaches a public repo. This
script checks tracked content and ignore status separately.

Usage:
    scan_leaks.py                       # scan the repo in the cwd, protect .local/
    scan_leaks.py --protect .local .secrets --root /path/to/repo
    scan_leaks.py --all                 # also scan untracked, non-ignored files

Exit codes: 0 clean, 1 findings, 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# An otpauth URI carries a seed only when it actually has a secret= value; the bare
# scheme appears constantly in documentation, regexes and prose, and flagging that
# trains people to ignore the scanner.
HARD = [
    (re.compile(r"otpauth://(?:totp|hotp)/\S*[?&]secret=([A-Za-z2-7=]{8,})", re.I),
     "otpauth:// URI carrying a shared secret"),
    (re.compile(r"otpauth-migration://offline\?data=([A-Za-z0-9%+/=]{16,})", re.I),
     "Google Authenticator export blob (contains every secret)"),
]
SUPPRESS = re.compile(r"scan-leaks:\s*ignore")
# A bare base32 blob is only a finding when the line also names a 2FA concept;
# base32-shaped strings are otherwise everywhere (hashes, IDs, tokens).
CONTEXT = re.compile(
    r"(totp|otp[_\- ]?secret|2fa|mfa|authenticator|shared[_\- ]?secret|recovery[_\- ]?code|backup[_\- ]?code)",
    re.I)
BASE32 = re.compile(r"\b[A-Z2-7]{16,}={0,6}\b")
# Placeholder secrets that appear in every tutorial; flagging them is noise.
KNOWN_EXAMPLES = {
    "JBSWY3DPEHPK3PXP",                  # "Hello!\xde\xad\xbe\xef"
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",  # RFC 6238 SHA-1 seed
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
}
SUSPECT_NAMES = re.compile(
    r"(backup|recovery)[-_.]?codes?|\.otpauth$|(^|/)totp[-_.].*\.(txt|json|env)$", re.I)
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".webp", ".ico"}

findings: list[str] = []


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


def scan_file(root: Path, rel: str) -> None:
    path = root / rel
    if path.suffix.lower() in BINARY_SUFFIXES or not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return
    for number, line in enumerate(text.splitlines(), 1):
        for reason in detect(line):
            findings.append(f"{rel}:{number}: {reason}")


def detect(line: str) -> list[str]:
    """Reasons this single line is a finding. The ONE detection path — scan_file and
    the self-test both call it, so the test cannot drift from what actually runs."""
    if len(line) > 4000 or SUPPRESS.search(line):
        return []
    reasons = []
    for pattern, what in HARD:
        match = pattern.search(line)
        if match and match.group(1).rstrip("=").upper() not in KNOWN_EXAMPLES:
            reasons.append(what)
    if CONTEXT.search(line):
        for match in BASE32.findall(line):
            if match.rstrip("=") not in KNOWN_EXAMPLES:
                reasons.append(f"base32 blob on a line naming 2FA ({len(match)} chars, "
                               f"starts {match[:4]}…) — likely a shared secret")
    return reasons


def selftest() -> int:
    """Guard the detection rules: a regression here silently misses a leaked seed."""
    # Every fixture line below carries the suppression marker so this scanner does not
    # report its own test data when scanning the repo it ships in. The marker is a
    # Python comment: the string literals themselves are untouched, so they still
    # exercise the real rules.
    should_flag = [
        "otpauth://totp/X:y?secret=MZXW6YTBOI7Q3PXPMZXW6YTB&issuer=X",  # scan-leaks: ignore  gitleaks:allow
        "a=otpauth://totp/X:y?issuer=X&algorithm=SHA1&secret=MZXW6YTBOI7Q3PXPMZXW6YTB",  # scan-leaks: ignore  gitleaks:allow
        "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SDlRlc3Qx",  # scan-leaks: ignore  gitleaks:allow
        "# my totp secret is MZXW6YTBOI7Q3PXPMZXW6YTB",  # scan-leaks: ignore  gitleaks:allow
        "TOTP_SECRET=MZXW6YTBOI7Q3PXPMZXW6YTB",  # scan-leaks: ignore  gitleaks:allow
    ]
    should_not_flag = [
        "sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # scan-leaks: ignore
        "id=ABCDEFGHIJKLMNOPQRST",  # base32-shaped, no context word — scan-leaks: ignore
        "otpauth://totp/LABEL?secret=BASE32&issuer=Ex",  # placeholder — scan-leaks: ignore
        "totp example secret JBSWY3DPEHPK3PXP",  # tutorial value — scan-leaks: ignore
        "otpauth://totp/x?secret=MZXW6YTBOI7Q3PXP  # scan-leaks: ignore",  # gitleaks:allow
        "an otpauth:// URI identifies a TOTP account",  # prose, no secret= value
    ]
    failures = 0
    for line in should_flag:
        if not detect(line):
            failures += 1
            print(f"FAIL missed: {line[:60]}", file=sys.stderr)
    for line in should_not_flag:
        if detect(line):
            failures += 1
            print(f"FAIL false positive: {line[:60]}", file=sys.stderr)
    if failures:
        print(f"selftest: {failures} failure(s)", file=sys.stderr)
        return 3
    print(f"selftest: OK ({len(should_flag) + len(should_not_flag)} checks)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--selftest", action="store_true", help="check the detection rules and exit")
    p.add_argument("--root", type=Path, default=Path.cwd(), help="repository root (default: cwd)")
    p.add_argument("--protect", nargs="*", default=[".local"],
                   help="paths that must be gitignored and untracked (default: .local)")
    p.add_argument("--all", action="store_true",
                   help="also scan untracked files that are not ignored (one `git add .` from a leak)")
    args = p.parse_args()

    if args.selftest:
        return selftest()

    root = args.root.resolve()
    if git(root, "rev-parse", "--git-dir").returncode != 0:
        print(f"scan-leaks: error: {root} is not a git repository", file=sys.stderr)
        return 2

    tracked = [f for f in git(root, "ls-files", "-z").stdout.split("\0") if f]
    for rel in tracked:
        scan_file(root, rel)
        if SUSPECT_NAMES.search(rel):
            findings.append(f"{rel}: tracked file whose name says it holds 2FA secrets")

    if args.all:
        others = [f for f in git(root, "ls-files", "-z", "--others",
                                 "--exclude-standard").stdout.split("\0") if f]
        for rel in others:
            before = len(findings)
            scan_file(root, rel)
            for i in range(before, len(findings)):
                findings[i] += "  [untracked but NOT ignored]"

    for protected in args.protect:
        target = root / protected
        if not target.exists():
            continue
        # Ask the question that actually matters — "would a NEW secret dropped in here
        # be ignored?" — with a probe path. Testing the directory itself is unreliable:
        # `.local/*` does not match `.local/`, and without --no-index git skips paths
        # already in the index, so a correctly-ignored dir can report as unignored.
        ignored = git(root, "check-ignore", "-q", "--no-index",
                      f"{protected.rstrip('/')}/__scan_leaks_probe__").returncode == 0
        inside = [f for f in tracked if f == protected or f.startswith(protected.rstrip("/") + "/")]
        # A path un-ignored by an explicit negation (the `dir/*` + `!dir/README.md`
        # idiom) is tracked on purpose. Its *content* is still scanned above, so
        # skipping it here drops a false positive without dropping coverage.
        inside = [f for f in inside
                  if git(root, "check-ignore", "-q", "--no-index", f).returncode == 0]
        if not ignored:
            findings.append(f"{protected}/: exists but is NOT gitignored — add it to .gitignore")
        if inside:
            findings.append(
                f"{protected}/: {len(inside)} file(s) already TRACKED by git "
                f"(e.g. {inside[0]}) — .gitignore does not apply to tracked files; "
                f"run: git rm --cached -r {protected} && rotate every secret in it")
        # A 700 directory gates traversal, so file modes inside it cannot be reached
        # by another user. Checking the directory is both the correct control and one
        # check instead of N noisy ones. POSIX only: Windows maps NTFS ACLs onto these
        # bits loosely, so the result there is not meaningful and is skipped.
        if sys.platform == "win32":
            pass
        elif target.is_dir() and target.stat().st_mode & 0o077:
            findings.append(f"{protected}/: mode {target.stat().st_mode & 0o777:o} — "
                            f"any local user can read it; run: chmod 700 {protected}")

    if findings:
        print(f"scan-leaks: {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print("\nAny secret that reached a commit must be rotated at the issuer — "
              "removing the file does not un-publish it.", file=sys.stderr)
        return 1
    scope = "tracked + untracked" if args.all else "tracked"
    print(f"scan-leaks: clean ({len(tracked)} {scope} file(s) scanned, "
          f"protected: {', '.join(args.protect) or 'none'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
