# 2FA secret storage backends

**Contents:** [macOS Keychain](#macos-keychain) · [Linux libsecret](#linux-libsecret) ·
[Windows](#windows-powershell-secretmanagement) · [pass](#pass-password-store) ·
[CI secret stores](#ci-secret-stores) · [Getting the seed out of a QR code](#getting-the-seed-out-of-a-qr-code) ·
[Rotation](#rotation) · [What each backend actually protects against](#what-each-backend-actually-protects-against) ·
[Sources](#sources)

`scripts/secret_store.py` wraps the first four uniformly. The raw commands are here
because you will need them when the wrapper is not installed, in a Dockerfile, or in
someone else's shell script.

## macOS Keychain

```bash
# write — the doubled stdin is deliberate, see below
printf '%s\n%s\n' "$SEED" "$SEED" | security add-generic-password -U -a bot -s totp -l 'totp: github' -w
# read
security find-generic-password -w -a bot -s totp
# delete
security delete-generic-password -a bot -s totp
# list services (attributes only, does not unlock any secret)
security dump-keychain | grep '"svce"<blob>='
```

`security add-generic-password -w` **with no value** prompts for the password and
then for a confirmation, both read as lines from stdin. Feeding the value twice is
the only non-interactive way to write a secret without putting it in `argv`. The
consequence: **the value must be a single line** — a multi-line value fails with
`passwords don't match`.

`dump-keychain` prints attributes in alphabetical order, so `"acct"` appears *before*
`"svce"` in each record. Parse per record, not as a stream, or every account gets
attributed to the previous item's service.

## Linux libsecret

```bash
printf '%s' "$SEED" | secret-tool store --label='totp: github' service totp account github
secret-tool lookup service totp account github
secret-tool search --all service totp
secret-tool clear service totp account github
```

`secret-tool store` reads the secret from stdin natively and handles multi-line
values. It needs a running secret service (GNOME Keyring, KWallet) with an unlocked
collection — in a headless container there is none, so fall back to a mode-600 file.

## Windows PowerShell SecretManagement

```powershell
Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore
Register-SecretVault -Name totp -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Set-Secret -Name github -Secret $seed -Vault totp
Get-Secret -Name github -Vault totp -AsPlainText
```

Pass the secret into PowerShell over stdin and read it with `[Console]::In.ReadToEnd()`
rather than interpolating it into the `-Command` string — the command line is visible
in Process Explorer and in PowerShell transcription logs.

## pass (password-store)

```bash
pass insert -m totp/github          # multi-line, reads from stdin
pass show totp/github
pass otp totp/github               # pass-otp extension generates the code directly
```

GPG-encrypted files in a git repo. Good when the secret must be shared with a small
team by key, but note that the *encrypted* seed then lives in version control
forever — rotation is the only way to revoke.

## CI secret stores

Use the provider's encrypted store and inject at run time; never commit the seed and
never `echo` it in a step.

| Provider | Inject as |
| --- | --- |
| GitHub Actions | `${{ secrets.TOTP_SEED }}` → `env:` on the step |
| GitLab CI | masked, protected CI/CD variable (masking needs a single-line value with no newlines) |
| CircleCI | context or project environment variable |

GitHub Actions masks a registered secret if it appears verbatim in a log, but not if
it is transformed (base32-decoded, split, base64'd). Do not rely on masking as a
control. A generated **code** is not a registered secret and will not be masked — it
is short-lived, but keep it out of logs anyway.

## Getting the seed out of a QR code

Almost every site offers a "can't scan the QR code?" or "enter this key manually"
link that shows the secret as text — take that instead of decoding an image.

If you only have the image, decode it **locally**:

```bash
zbarimg --raw qr.png          # zbar-tools
```

Never upload a 2FA QR code to a web decoder: the image *is* the secret, and it does
not expire.

Google Authenticator's "export accounts" QR is
`otpauth-migration://offline?data=<base64 protobuf>` — an undocumented,
reverse-engineered format that carries **every** exported account's seed. Decode it
once into individual `otpauth://` URIs, store those, and destroy the blob.

## Rotation

Rotating a TOTP seed means re-enrolling at the issuer; there is no way to invalidate
a seed from your side. After any exposure:

1. Disable and re-enable 2FA at the issuer to get a fresh seed.
2. Regenerate backup codes — the old set stays valid until you do.
3. Store the new seed, delete the old entry.
4. Change the account password too if the seed sat next to it.

Deleting a file or force-pushing does **not** un-publish a secret that reached a
remote: assume it is captured.

## What each backend actually protects against

| Threat | Keychain | 600 file | Gitignored repo file | Env var |
| --- | --- | --- | --- | --- |
| Committed to git by accident | yes | yes | only if never tracked | yes |
| Another local user reads it | yes | yes (700 dir) | yes (700 dir) | no (same-user `ps -E`) |
| Malware running **as you** | no | no | no | no |
| Repo archived/copied wholesale | yes | yes | **no** | yes |
| Leaked into CI logs | yes | yes | yes | only if masked |

Nothing on this list defends against code running as the user. An agent with shell
access can read any of these — the seed's protection is the machine's, not the
store's.

**Windows caveat:** the `700`/`600` mode bits above are POSIX. Windows maps them onto
NTFS ACLs only loosely, so a mode check there proves nothing — `scan_leaks.py` skips
it rather than report a meaningless pass. On Windows, use the PowerShell SecretStore
vault and rely on ACL inheritance from a user-profile directory, not on chmod.

## Sources

- `security(1)` — <https://ss64.com/mac/security.html>
- `secret-tool(1)` — <https://manpages.debian.org/unstable/libsecret-tools/secret-tool.1.en.html>
- PowerShell SecretManagement — <https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview>
- pass — <https://www.passwordstore.org/>
- GitHub Actions secrets and masking — <https://docs.github.com/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions>
