---
name: totp-generate
description: Generates a current RFC 6238 TOTP two-factor code from a shared secret the user already holds, via a bundled zero-dependency script that parses otpauth:// URIs and handles window expiry. Use when the user asks for a 2FA code, OTP, authenticator code, or why generated codes are always rejected. Not for storing secrets or backup codes, password-manager APIs, or retrying a code during a login.
license: MIT
---

# totp-generate

Turn a TOTP shared secret into the code the service is asking for, right now,
offline. Fixes the failures that make hand-rolled TOTP unreliable: leading zeros
dropped, base32 padding computed before whitespace is stripped, `digits`/`period`
from an `otpauth://` URI ignored, codes handed over with two seconds of life left,
and host clock drift misdiagnosed as a wrong secret.

## When NOT to use

- Deciding **where the secret lives** (keychain, env, gitignored file), enrolling
  from a QR code, or handling backup codes → `totp-secret-store`.
- The seed is in **1Password, Bitwarden, Vault, or 2FAuth** and you fetch the code
  over their CLI/API → `totp-provider-api`.
- Serving codes to MCP clients as a tool → `totp-mcp-server`.
- Detecting the challenge, filling the form, retrying → `login-2fa-flow`.
- Building TOTP **verification** into your own app (you are the server checking a
  user's code) — that is ordinary application code, not this skill.
- `otpauth://hotp/…` — counter-based, needs persistent counter state. Say so and stop.

## Ground rules

1. **Never put a secret in `argv`.** Command-line arguments are visible to every
   process on the host via `ps` and land in shell history. Use `--file`, `--stdin`,
   or the environment. (Environment is better than `argv` but still readable by the
   same user via `ps -E` / `/proc/PID/environ`; a file with mode `600` is best.)
2. **Never print the secret.** Print the code. If a user pastes a secret inline,
   answer, then tell them the file/stdin form for next time.
3. **A code is single-use and short-lived.** Do not write it to a file, a commit, a
   PR body, or a log. If a submission is rejected, **do not resend the same digits** —
   wait for the next window.
4. Only generate codes for accounts the user controls or is authorized to automate.

## Workflow

### 1. Locate the secret without reading it into context

```bash
TOTP="${CLAUDE_SKILL_DIR}/scripts/totp.py"

python3 "$TOTP" --file ~/.config/totp/github.txt          # file (preferred)
security find-generic-password -w -s totp-github | python3 "$TOTP" --stdin   # macOS keychain
secret-tool lookup service totp account github | python3 "$TOTP" --stdin     # Linux libsecret
TOTP_SECRET=… python3 "$TOTP"                             # env var
```

The file or stdin may hold a raw base32 secret **or** a full `otpauth://totp/…` URI;
the script detects which and reads `digits`, `period`, and `algorithm` from the URI.

### 2. Generate

```bash
python3 "$TOTP" --file SECRET_FILE                        # -> 6 digits on stdout
python3 "$TOTP" --file SECRET_FILE --min-validity 5       # wait out a dying window first
python3 "$TOTP" --file SECRET_FILE --json                 # {"code":…,"expires_in":…}
```

Use `--min-validity 5` (or more, for a slow form) **whenever the code is about to be
typed or submitted somewhere**. Without it, a code generated at second 29 of a
30-second window is dead before the form posts — the single most common cause of
"the code was wrong" in automation.

Report the code **and** its remaining validity: `123456 (valid 24s)`.

### 3. When a code is rejected, diagnose in this order

```bash
python3 "$TOTP" --check-clock      # exit 4 = host clock drift; fix the clock, not the code
python3 "$TOTP" --selftest         # exit 3 = implementation broken (should never happen)
python3 "$TOTP" --file SECRET_FILE --window 1 --json   # what neighbouring windows would give
```

Clock drift is the first suspect, not the last. Then check `digits` / `period` /
`algorithm` against what the issuer expects — a 6-digit generator against an 8-digit
issuer is silently wrong forever. `--window` is a **diagnostic**: it shows whether the
server would have accepted an adjacent window. Never submit a windowed code.

## Output spec

- Exactly one code on stdout, zero-padded to the full digit count, plus the remaining
  validity in your message to the user.
- The secret never appears in output, in a file, or in the transcript.
- Non-zero exit means no code was produced: `2` usage/secret error, `3` self-test
  failure, `4` clock drift. Surface the script's stderr message verbatim; it names
  the fix.

## Code-source contract

Other skills in this set never import this one. They invoke a **code command**: any
shell command that prints the code and nothing else on stdout, exits 0, and returns a
code with at least ~5 seconds of life. This script satisfies all three with
`--min-validity 5`; diagnostics go to stderr. Keep that interface when you wire
generation into a script or test fixture — `login-2fa-flow`'s preflight enforces it.

## Gotchas

| Symptom | Cause and fix |
| --- | --- |
| Code rejected, secret definitely correct | Host clock drift — `--check-clock` first |
| `Incorrect padding` from base32 | Strip spaces/hyphens **then** pad; the bundled script does |
| Code is 5 letters | Steam (`encoder=steam`); Steam's own `shared_secret` is base64, not base32 |
| Works locally, fails in CI | Runner clock, or the code aged out during a slow step — add `--min-validity` |
| Retry after "invalid code" fails too | Same digits resubmitted inside one window; wait for the next |
| Secret contains `0`, `1`, `8` or `9` | Not valid base32 (RFC 4648) — a transcription error, usually `0`↔`O` or `1`↔`l` |
| Two accounts, one secret file | One secret per file; `--file` reads the first non-comment line |

## References

- `references/totp-spec.md` — RFC 6238/4226 essentials, the `otpauth://` parameter
  table, the Appendix B test vectors, and the verifier behaviours (single-use per
  step, ±1 step tolerance) that dictate the retry rule.
- `scripts/totp.py` — the generator. `--help` lists every flag; `--selftest` proves it
  against the RFC vectors in under a second.
