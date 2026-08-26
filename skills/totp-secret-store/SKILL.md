---
name: totp-secret-store
description: Stores and retrieves 2FA shared secrets and single-use backup codes safely - OS keychain, gitignored directory, or CI secret store - and scans a repo for leaked seeds. Use when the user asks where to keep a TOTP secret, to save recovery or backup codes, to enrol from a QR code, or to stop committing a seed. Not for generating a code or fetching one from a password-manager API.
license: MIT
---

# totp-secret-store

Decide where a TOTP seed and its backup codes live, put them there, and prove they
are not in git. Fixes the failures that actually burn people: a seed committed
because `.gitignore` does not apply to already-tracked files, secrets passed as
command arguments and captured by `ps` and shell history, backup codes reused after
they were spent, and "I deleted the file" treated as remediation for a published
secret.

## When NOT to use

- Producing a code from a secret → `totp-generate`.
- The seed lives in 1Password / Bitwarden / Vault / 2FAuth and you never hold it →
  `totp-provider-api`.
- Serving codes to MCP clients → `totp-mcp-server`. Driving a login → `login-2fa-flow`.
- Generic secret handling (API keys, `.env`, cloud credentials) — not 2FA-specific,
  and no reason to load this skill.

## Say this once, plainly

A TOTP seed stored next to the password it protects **collapses two-factor to one
factor** for whoever holds that machine. That is a legitimate, deliberate trade for a
machine account doing automated logins — it is not "secure 2FA". State it, then do
the work. Two mitigations that cost nothing:

- Enrol a **dedicated service/bot account** with its own seed rather than reusing a
  human's personal seed. Compromise is then scoped and revocable without touching a
  person's identity.
- Keep the seed and the password in **different** stores where the platform allows.

Only set up automation for accounts the user owns or is authorised to automate.

## Where to put it — in order

| Rank | Location | Use when |
| --- | --- | --- |
| 1 | OS keychain (macOS Keychain, libsecret, PowerShell SecretStore) | Default. Encrypted at rest, unlocked with the login session. |
| 2 | File **outside** the repo, mode 600, in a 700 directory (`~/.config/totp/`) | No keychain (containers, headless CI images). |
| 3 | Gitignored directory **inside** the repo (`.local/`), 700 | The user wants it beside the project. Weaker: repos get tarred, copied into sandboxes, indexed by editors, and `git add -f` overrides the ignore. |
| 4 | Environment variable | CI, where the provider's encrypted secret store injects it. Visible to child processes and to `ps -E` / `/proc/PID/environ` for the same user. |
| — | Command-line argument | **Never.** World-readable via `ps`, recorded in shell history. |

## Workflow

### 1. Enrol

Get the `otpauth://` URI, not a photo of a QR code — most sites show a "can't scan
it?" link that reveals the secret as text. If you only have the image, decode it
locally (`zbarimg qr.png`); never upload a 2FA QR code to an online decoder.

```bash
STORE="${CLAUDE_SKILL_DIR}/scripts/secret_store.py"

python3 "$STORE" backends                                  # what's available here
printf '%s' 'otpauth://totp/GitHub:bot?secret=…' | python3 "$STORE" set github
```

The secret goes in over **stdin**. `set` refuses a terminal, so it can never be typed
into a place that records it.

### 2. Verify the round trip without revealing the seed

```bash
python3 "$STORE" describe github     # structure + validity, no secret
python3 "$STORE" get github | python3 /path/to/totp-generate/scripts/totp.py --stdin
```

A code comes out; the seed never enters the transcript. This pipe is the standard
composition — no skill ever hands a seed to another through the model's context.

**`get` belongs on the left of a pipe and nowhere else.** Running it alone — to check
what is stored, or to debug a failing pipeline stage — puts the seed on stdout, and
from there into the transcript, the harness log, and whatever ships those onwards. Use
`describe` for that; it reports the URI's issuer, digits, period, algorithm and secret
*length* without the secret. A leaked code is worth 30 seconds; a leaked seed is
permanent and silent, and the only remedy is re-enrolling at the issuer.

### 3. Backup codes

Store them under a separate namespace so a compromise of one is not both:

```bash
printf '%s' "$CODES" | python3 "$STORE" set github --service totp-backup
python3 "$STORE" get github --service totp-backup --pop   # hands out one, keeps the rest
```

Backup codes are **single-use and password-equivalent** — each one bypasses 2FA
completely. `--pop` writes the remainder back *before* printing, so a crash loses a
code rather than reissuing a spent one; the file backend's write is atomic, so the
*other* codes always survive. Capture the output — a popped code is gone from the
store. When the list runs out, regenerate at the issuer; do not reuse.

**`--pop` is not a code command.** It satisfies the shape of one — a single code on
stdout, exit 0 — but it consumes state, and everything that consumes a code command
runs it more than once: a preflight check invokes it twice, a login retry invokes it
again. Wiring it into automation destroys several codes and then fails, because two
backup codes are never equal. Spending one is a deliberate decision a human makes.

Multi-line input is stored as one `|`-separated line, because macOS's keychain writer
reads a single line. Each code is preserved exactly, including internal spaces
(`1234 5678` stays one code), and `get` prints a list one per line. A single-value
secret is stored verbatim, so the pipe in step 2 is unaffected.

### 4. If they must live in the repo

```bash
mkdir -m 700 -p .local/2fa
grep -qxF '.local/' .gitignore || printf '.local/\n' >> .gitignore
git check-ignore -q .local/ && echo ignored || echo "NOT IGNORED"
git ls-files --error-unmatch .local 2>/dev/null && echo "ALREADY TRACKED — see below"
```

**`.gitignore` has no effect on files git already tracks.** If anything under the
path is tracked, `git rm --cached -r .local` and then **rotate the secret at the
issuer** — it is in the object database and possibly on a remote.

### 5. Scan before publishing

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/scan_leaks.py" --protect .local --all
```

Exits non-zero on findings. `--all` also covers untracked, non-ignored files — one
`git add .` from being committed. Add `# scan-leaks: ignore` to a line that is
genuinely documentation. The scanner never reads the contents of protected
directories; it only checks their mode, ignore status, and tracking.

## Output spec

- The secret is stored and a **round-trip check has produced a code**; the seed itself
  never appeared in output, in the transcript, or in any repo file.
- The location, the backend, and its rank in the table above were stated to the user.
- `scan_leaks.py` exits 0, or every finding was explained and remediated.
- Exit codes from `secret_store.py`: `2` usage, `3` not found, `4` backend failure.

Both scripts carry a self-check — `secret_store.py selftest` (value round-tripping,
where silent corruption would live) and `scan_leaks.py --selftest` (the detection
rules, including the false positives they must *not* raise). Run them after editing
either script or on a machine where something behaves unexpectedly.

## Gotchas

| Symptom | Cause and fix |
| --- | --- |
| Seed still in `git status` after adding to `.gitignore` | Already tracked — `git rm --cached`, then rotate at the issuer |
| `passwords don't match` from `security` | A multi-line value hit macOS's line-based prompt; the script normalises to one line |
| `bw`/`op` entry found but seed not in keychain | It is a provider-hosted seed → `totp-provider-api`, not this skill |
| Backup code rejected | Already spent — they are single-use; use `--pop` so this cannot happen twice |
| Secret works locally, missing in CI | Keychain needs an unlocked login session; use the CI secret store and an env var |
| `.local/` readable by other users | Directory mode; `chmod 700 .local` — the directory bit, not the file bits, gates access |

## References

- `references/backends.md` — exact commands per platform (macOS `security`, libsecret,
  PowerShell SecretStore, `pass`, CI secret stores), what each protects against, and
  the QR-decoding and rotation procedures.
