# Setup prompt

Paste-ready `/goal` for wiring these five skills into a working 2FA-automation setup
in one session. Replace the bracketed values first. Each skill resolves its own
script paths, so the prompt names skills rather than hard-coded file locations.

```text
/goal Set up 2FA automation for [ACCOUNT] (issuer: [SERVICE]) on this machine so an agent can complete its login unattended. Work through the phases in order; a phase is done only when its verifier command exits 0. NEVER run git commit or git push — leave every change in the working tree for me to review.

Authorisation: [ACCOUNT] is an account I own or am authorised to automate. If anything suggests otherwise, stop and ask.

Phase 1 — CUSTODY (skill: totp-secret-store). Blocking; nothing else may start until it passes.
- Run the skill's backend check and tell me which backend it picked and why.
- I will hand you the otpauth:// URI. Take it over stdin only — never as a command argument, never echoed back, never written into a repo file or this transcript.
- If backup codes exist, store them under a separate service namespace from the seed.
- If any secret must live in this repo, put it under a 700 .local/ directory and prove with git check-ignore AND git ls-files that it is both ignored and untracked.
- VERIFIER: the skill's leak scanner exits 0 with .local protected, and a piped get|generate round trip prints a code without the seed appearing anywhere.

Phase 2 — GENERATION (skill: totp-generate). Depends on Phase 1.
- Confirm the implementation and the host: run the script's RFC 6238 self-test and its clock check.
- Produce one live code and report its remaining validity. Do not write the code anywhere.
- VERIFIER: self-test exits 0, clock check exits 0, and one code is produced with >5s validity.

Phase 3 — SERVING (parallel; the two tracks touch disjoint files, so run them concurrently only if I asked for both). Depends on Phase 2.
- Track A (skill: totp-mcp-server) — touches .mcp.json and the server's env only. Register the bundled server as a stdio server with an ABSOLUTE path. Set an explicit account allowlist; an empty allowlist exposes every enrolled account. Put account NAMES in the config and no secrets. Tell me to restart the session, since stdio tools are discovered at session start.
  VERIFIER: after restart, the server lists its tools and returns one code, and the audit log has gained a line.
- Track B (skill: totp-provider-api) — touches CI config and shell env only. Use it INSTEAD of Phase 1 custody if the seed should live in a vault rather than on this machine; say so plainly if you think that is the better fit here.
  VERIFIER: the provider check reports the target provider as ready, and one fetch prints a code and exits 0.

Phase 4 — THE LOGIN (skill: login-2fa-flow). Depends on Phase 2, and on Phase 3 if I asked for it.
- Run the skill's preflight against the code command chosen above BEFORE touching [SERVICE]. Do not attempt a login until preflight exits 0.
- Prefer reusing a saved session over running the challenge. Wire the login so the session is saved to a gitignored path afterwards.
- Generate the code immediately before submitting, with a validity margin.
- Hard limit: at most TWO code submissions. If both fail, stop and report — do not loop. If the challenge turns out to be push, WebAuthn, SMS or a CAPTCHA, stop and tell me; those cannot be scripted.
- VERIFIER: preflight exits 0, then either a successful login with session state written to a gitignored path, or a clear explanation of why it stopped.

Closing verification (re-run, do not assume Phase 1 still holds):
- The leak scanner exits 0.
- git status shows no secret in the working tree, and no file staged that contains a seed, a backup code, or a token.
- Report: backend chosen, code command used, files changed, and anything you could not verify.

Definition of done: every phase verifier above exited 0, or you stopped with a specific reason. Do not report success on a phase whose verifier you did not actually run.
```

## Notes

- **Ordering is real.** Phases 2–4 each consume the artefact of the previous one; a
  preflight against a code command that does not exist yet just fails.
- **Phase 3's two tracks are alternatives as often as they are both.** Track B replaces
  local custody entirely — if the seed belongs in a vault, Phase 1 is the wrong shape
  and the agent should say so.
- **Verification is bracketed**: the leak scan runs at the end of Phase 1 and again at
  the close, because later phases write config files and session state.
- **No git actions.** The prompt says so twice on purpose; agents drift toward
  committing when a task feels finished.
