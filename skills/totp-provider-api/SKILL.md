---
name: totp-provider-api
description: Fetches 2FA codes from a managed provider's API or CLI - 1Password (op), Bitwarden (bw), Vault's TOTP engine, 2FAuth - so the seed never lands on this machine. Use for an OTP from a password manager or team-shared 2FA, when such a CLI returns an ambiguous item or more than one result, or when asking whether a provider has a usable API. Not for local seed files or offline generation.
license: MIT
---

# totp-provider-api

Get a code from a provider that holds the seed for you. The machine running the
agent never has the secret, the provider logs every request, and access is revoked
by disabling a token rather than by chasing files. Fixes the failure that wastes the
most time here: a vendor CLI silently falling back to an **interactive unlock**, so
an unattended job hangs until it is killed.

## Which skill, in one question

**Do you hold the seed?** If yes — a file, keychain entry, or `otpauth://` URI on
this machine — that is `totp-generate` plus `totp-secret-store`. If the seed lives in
a vault you authenticate to and never see, it is this skill. `op item get --otp`
computes locally inside the `op` binary, but you never hold the seed, so it is here.

## When NOT to use

- Generating from a seed you have → `totp-generate`.
- Choosing where a seed you hold should live → `totp-secret-store`.
- Serving codes to MCP clients → `totp-mcp-server`. Driving the login → `login-2fa-flow`.
- **Verifying your end users' TOTP codes** (you are the service, they are the user) —
  that is Twilio Verify / an application TOTP library, the opposite direction. Not
  this skill.

## Provider reality check

| Provider | How a code is fetched | Auth |
| --- | --- | --- |
| **1Password** | `op item get ITEM --otp`; `op read "op://v/i/one-time password?attribute=otp"`; SDK `secrets.resolve(...)` | `OP_SERVICE_ACCOUNT_TOKEN` |
| **Bitwarden** | `bw get totp ITEM_ID` | `BW_SESSION` from `bw unlock --raw` |
| **HashiCorp Vault** | `GET /v1/totp/code/:name` — plain HTTP, no client needed | `X-Vault-Token` |
| **2FAuth** (self-hosted) | `GET /api/v1/twofaccounts/{id}/otp` | `Authorization: Bearer` PAT |
| **Google Authenticator** | **No API exists.** | — |

Google Authenticator is a phone app with no server API and no CLI. Its only egress is
the `otpauth-migration://offline?data=…` export QR — an undocumented, reverse-engineered
protobuf. If someone asks to "use the Google Authenticator API", say it does not
exist and pick from the rows above. Decode the migration blob once into `otpauth://`
URIs and move on.

Best pure-HTTP API: **Vault** (one GET, a token header, every request audited).
Best if the team already has it: **1Password** (service accounts are built for this).
Best fully self-hosted with a UI: **2FAuth**.

## Workflow

### 1. Check the credential before you call anything

```bash
FETCH="${CLAUDE_SKILL_DIR}/scripts/fetch_code.py"
python3 "$FETCH" check          # which providers are installed and credentialed
```

`op` and `bw` prompt for an interactive unlock when their credential is missing —
in CI or an unattended agent that is a hang, not an error. The script checks first,
closes stdin, and enforces a 30 s timeout, so it always fails fast and loudly.

### 2. Fetch

```bash
python3 "$FETCH" 1password "GitHub" --vault Automation --min-validity 5
python3 "$FETCH" bitwarden 99ee88d2-0000-0000-0000-000000000000 --min-validity 5
python3 "$FETCH" vault github --addr https://vault.internal:8200
python3 "$FETCH" 2fauth 3 --url https://2fauth.internal
```

**Use `--min-validity 5` whenever the code is going into a form.** A provider returns
bare digits with no hint of how long they last, and the network round trip is pure
loss on top. TOTP windows are absolute — `floor(unix_time / period)` is the same
window for you and for the issuer — so the script can wait for a fresh window
*before* fetching. Without it, a code fetched near a boundary is rejected in a way
indistinguishable from a wrong seed, and it costs one of your two login attempts.
Pass `--period` if the account does not use 30 seconds.

One code on stdout, exit 0. Non-zero and nothing on stdout otherwise: `3` not found
or ambiguous, `5` credential missing/expired, `6` timeout, `7` provider error. This
is the same **code command** contract the rest of these skills consume — anything
that prints one code and exits 0 is interchangeable. The script also refuses output
that is not exactly one code-shaped line, so a `bw` sync notice or an `op`
deprecation banner can never be submitted as a code.

Raw vendor equivalents, when the script is not available:

```bash
op item get "GitHub" --otp                                     # not with --fields
op read "op://Automation/GitHub/one-time password?attribute=otp"
bw get totp "$ITEM_ID" --nointeraction
curl -sH "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/totp/code/github" | jq -r .data.code
curl -sH "Authorization: Bearer $TWOFAUTH_TOKEN" "$TWOFAUTH_URL/api/v1/twofaccounts/3/otp" | jq -r .password
```

### 3. Scope the credential

- 1Password: a **service account** with access to one dedicated vault. Service
  accounts cannot reach Private vaults, and `--vault` is required once more than one
  is visible. `OP_CONNECT_HOST`/`OP_CONNECT_TOKEN` take precedence over the service
  account token — unset them if a Connect setup is interfering.
- Vault: a policy granting `read` on exactly `totp/code/<name>`. Do not grant
  `totp/keys/*`, which exposes the seed URL.
- 2FAuth: a personal access token, revocable in Settings. It is valid until revoked.
- Always prefer a **dedicated machine account** at the upstream service over a
  human's personal 2FA.

### 4. Keep it out of the logs

Never echo the token. A fetched code is short-lived but is still a credential — do
not print it in CI output, and remember CI secret masking only covers registered
secrets, not values a provider returns at run time.

## Output spec

- One code on stdout; the token never appears in output, logs, or the transcript.
- The provider, the item identity used, and the credential source were stated.
- Non-zero exits surfaced verbatim — each message names the fix.

## Gotchas

| Symptom | Cause and fix |
| --- | --- |
| `op`/`bw` hangs forever in CI | Falling back to an interactive unlock — set the token/session; a longer timeout is not a fix |
| `More than one result was found` | Ambiguous item name — use the item **ID** |
| `cannot use '--otp' and '--fields' together` | Fetch the password and the OTP as two calls |
| `op read` returns `otpauth://…` instead of digits | Missing `?attribute=otp` — you got the seed, not the code |
| Service account cannot see the item | It is in a Private vault, or the vault was never shared with the account |
| Vault 403 on `totp/code/x` | Policy grants the key path but not the code path |
| 2FAuth returns HTML | Base URL points at the web UI, not `/api/v1` |
| Codes fine locally, rejected from CI | Provider-side generation is immune to *your* clock, but the runner's clock still matters if anything local also generates |

## References

- `references/providers.md` — per-provider setup, exact endpoints and response
  shapes, rate limits, token scoping, the Google Authenticator export format, and
  where Twilio Verify TOTP actually fits.
