# Changelog

All notable changes to this repository's skills are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org) on the plugin manifest
(breaking skill-interface change → major, new skill → minor, fix → patch).

## [Unreleased]

### Added
- `totp-generate` — offline RFC 6238 code generation from a held seed. Ships
  `scripts/totp.py` (standard library only): `otpauth://` parsing, `--min-validity`
  to wait out a dying window, `--window` drift diagnosis, `--check-clock`, Steam
  encoder, and `--selftest` against the RFC 6238 Appendix B vectors.
- `totp-secret-store` — custody of seeds and single-use backup codes across macOS
  Keychain, libsecret, PowerShell SecretStore and mode-600 files, with `--pop` for
  spending a backup code exactly once, plus `scripts/scan_leaks.py` to catch seeds
  that are committed, tracked despite `.gitignore`, or in a world-readable directory.
- `totp-mcp-server` — self-hostable MCP server (stdio, `mcp` SDK v2 pinned via PEP
  723) exposing two read-only tools, with an account allowlist enforced before any
  secret access, per-account rate limiting, and an append-only audit log. No tool can
  store, read or export a secret.
- `totp-provider-api` — codes from 1Password, Bitwarden, HashiCorp Vault's TOTP
  secrets engine and 2FAuth behind one exit-code contract, with credential
  preconditions checked up front so an unattended run fails fast instead of hanging on
  an interactive unlock.
- `login-2fa-flow` — driving the 2FA challenge step of an automated login: session
  reuse first, `scripts/preflight.py` to validate the code source without touching the
  target site, one fresh code per attempt, and a two-attempt cap before lockout.
- `docs/setup-prompt.md` — paste-ready `/goal` that wires the five skills together.
- Repository scaffolded from the skills template.

### Notes

The **code-command contract** shared by all five skills is: print the code and nothing
else on stdout, exit 0, return a code with at least ~5 seconds of life, and be
idempotent. `preflight.py` enforces all four, so a vendor CLI's banner on stdout, a
code fetched at a window boundary, or a backup-code source that consumes a code per
call is caught off-site instead of costing a login attempt or a recovery code.

`login-2fa-flow` requires **origin verification before the code is typed**. A TOTP code
has no origin binding, so no code source can tell where its digits are going — the
check has to happen at the form, and it is the only defence against an agent being
talked into entering a valid code on an attacker's page.

External review (three flagship models plus two independent reviewers) shaped several
decisions worth recording: `get_totp_code` is documented as a **code oracle** rather
than as a boundary the allowlist and audit log do not actually provide;
`secret_store.py describe` exists so nothing ever needs to run `get` alone to inspect
a stored value; and the login attempt cap is stated as per-account-across-runs,
because the issuer's failed-attempt counter is durable and no skill here can read it.
