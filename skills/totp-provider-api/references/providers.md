# TOTP providers with a machine-usable API

**Contents:** [1Password](#1password) · [Bitwarden](#bitwarden) ·
[HashiCorp Vault](#hashicorp-vault-totp-secrets-engine) · [2FAuth](#2fauth-self-hosted) ·
[Google Authenticator](#google-authenticator-no-api) ·
[Twilio Verify — the other direction](#twilio-verify-totp--the-other-direction) ·
[Choosing](#choosing) · [Sources](#sources)

Verified 2026-08-26. Every command below was taken from the vendor's own
documentation; re-check before relying on a flag in a pipeline.

## 1Password

**Setup.** Create a service account, grant it a **dedicated vault** (service accounts
cannot access Private vaults), then:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
op item get "GitHub" --otp --vault Automation
op read "op://Automation/GitHub/one-time password?attribute=otp"
```

Requires CLI ≥ 2.18.0. `--vault` becomes mandatory once the account can see more
than one vault.

**Gotchas.**

- `--otp` **cannot** be combined with `--fields`; the CLI rejects it. Fetch the
  password and the OTP as two calls (one authentication covers both in a one-liner).
- Without `?attribute=otp`, `op read` returns the `otpauth://` **seed URI**, not a
  code. Getting a long base32 string back means you fetched the secret itself.
- `OP_CONNECT_HOST` / `OP_CONNECT_TOKEN` take **precedence** over
  `OP_SERVICE_ACCOUNT_TOKEN`. Unset them if a Connect config is shadowing your
  service account.
- Service accounts have hourly and daily rate limits that also apply through the SDKs.

**SDKs** (no CLI binary needed) — Python, JavaScript, Go:

```python
client = await Client.authenticate(auth=os.environ["OP_SERVICE_ACCOUNT_TOKEN"],
                                   integration_name="ci", integration_version="v1")
code = await client.secrets.resolve("op://Automation/GitHub/one-time password?attribute=otp")
```

Early beta SDK versions did not support query parameters on references; upgrade if
`?attribute=otp` is rejected.

## Bitwarden

```bash
export BW_SESSION=$(bw unlock --raw)
bw get totp "$ITEM_ID" --nointeraction
```

- `bw login` with email/password unlocks automatically; API-key and SSO logins
  require a separate `bw unlock`.
- The session key dies on `bw lock` / `bw logout` and does **not** cross terminals.
  `--session <key>` passes it per invocation instead.
- `bw get totp <name>` fails with *"More than one result was found"* when the term
  matches several items — it does not prefer the one with a TOTP. Use the item ID.
- `--nointeraction` (a global flag) suppresses prompts, turning a hang into an error.

## HashiCorp Vault TOTP secrets engine

Vault becomes the authenticator: it stores the seed, generates codes on request, and
audits every one. RFC 6238 compliant.

```bash
vault secrets enable totp

# import an existing account from the issuer's otpauth URL (generate=false)
vault write totp/keys/github url="otpauth://totp/GitHub:bot?secret=...&issuer=GitHub"

# or have Vault generate a brand new key to enrol at the issuer
vault write totp/keys/github generate=true issuer=GitHub account_name=bot

vault read totp/code/github            # -> code
```

HTTP, no client binary:

```bash
curl -sH "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/totp/code/github"
# {"data": {"code": "810920"}}
```

| Operation | Endpoint |
| --- | --- |
| Create key | `POST /v1/totp/keys/:name` |
| Read key metadata | `GET /v1/totp/keys/:name` (never returns the seed) |
| List keys | `LIST /v1/totp/keys` |
| **Generate code** | `GET /v1/totp/code/:name` |
| Validate a code | `POST /v1/totp/code/:name` with `{"code": "..."}` → `{"valid": true}` |
| Delete key | `DELETE /v1/totp/keys/:name` |

Key parameters: `generate` (bool, default false), `exported` (bool, default true —
returns a QR barcode and URL when generating), `key_size` (default 20), `url`, `key`,
`issuer`, `account_name`, `period` (default 30), `algorithm` (default SHA1),
`digits` (default 6), `skew` (default 1), `qr_size` (default 200).

**Scope the policy to the code path only.** `totp/keys/*` can expose the seed URL;
`totp/code/<name>` cannot:

```hcl
path "totp/code/github" { capabilities = ["read"] }
```

Paths assume the engine is mounted at `totp/`; adjust for another mount.

## 2FAuth (self-hosted)

Open-source web app over a REST API (OpenAPI 3.1), useful when you want a browsable
UI plus machine access on your own infrastructure.

```bash
curl -sH "Authorization: Bearer $TWOFAUTH_TOKEN" \
     "$TWOFAUTH_URL/api/v1/twofaccounts/3/otp"
# {"password": "654321", "otp_type": "totp", "period": 30, ...}
```

- Token: **Settings → OAUTH → generate a new token**. Valid until revoked (RFC 6750
  bearer scheme).
- `GET /api/v1/twofaccounts` lists accounts and their IDs.
- `POST /api/v1/twofaccounts/otp` generates from an arbitrary `otpauth://` URI
  without persisting it.
- Getting HTML back means the base URL points at the UI rather than `/api/v1`.
- Self-hosting means you own the patching: CVE-2024-52598 was an SSRF in
  `/api/v1/twofaccounts/preview`. Stay current and keep it off the public internet.

## Google Authenticator: no API

There is no server API, no CLI, and no supported programmatic export. The only
egress is the in-app **Transfer accounts → Export accounts** QR, which encodes
`otpauth-migration://offline?data=<base64 proto3>` — a reverse-engineered format with
no published schema, carrying **every** exported account's seed at once.

If you need programmatic codes, move the accounts to one of the providers above.
Decode the migration blob **locally** (never in a web tool), split it into individual
`otpauth://` URIs, enrol those, and destroy the blob.

## Twilio Verify TOTP — the other direction

Twilio Verify TOTP is for **you verifying your users**: you create a Factor for a
user, they scan it into their authenticator, and you POST their typed code to a
Challenge endpoint. It does not give you codes for accounts you hold elsewhere —
opposite direction, different problem.

The legacy **Authy API is closed to new customers** and deprecated; Twilio directs
new development to Verify v2, and publishes a seed-export path for migrating
existing Authy TOTP users. The Authy helper libraries (Ruby, PHP, Python) are all
archived.

## Choosing

| Constraint | Pick |
| --- | --- |
| Plain HTTP, no client, full audit trail | Vault TOTP engine |
| Team already on 1Password | 1Password service account |
| Team already on Bitwarden | Bitwarden CLI + session key |
| Self-hosted, wants a UI too | 2FAuth |
| "Use the Google Authenticator API" | Does not exist — migrate the accounts |
| Verifying *your users'* codes | Twilio Verify or an app-side TOTP library |

## Sources

- 1Password secret references — <https://www.1password.dev/cli/secret-references/>
- 1Password service accounts — <https://developer.1password.com/docs/service-accounts/use-with-1password-cli/>
- 1Password SDKs — <https://developer.1password.com/docs/sdks/load-secrets/>
- Bitwarden CLI — <https://bitwarden.com/help/cli/>
- Vault TOTP HTTP API — <https://developer.hashicorp.com/vault/api-docs/secret/totp>
- Vault TOTP engine — <https://developer.hashicorp.com/vault/docs/secrets/totp>
- 2FAuth API — <https://github.com/Bubka/2FAuth-Docs/blob/main/docs/API.md>
- Twilio Verify vs Authy — <https://www.twilio.com/docs/verify/authy-vs-verify>
- Key Uri Format — <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
