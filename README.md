# 2fa Agents

[![CI](https://github.com/Paldom/2fa-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/Paldom/2fa-agents/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![skills.sh](https://skills.sh/b/Paldom/2fa-agents)](https://skills.sh/Paldom/2fa-agents)

Agent Skills for two-factor authentication in agent workflows: RFC 6238 TOTP code generation, secret storage and retrieval, and driving the 2FA step of automated logins.

Agent Skills for [Claude Code](https://code.claude.com/docs/en/skills) (and any
[Agent Skills](https://agentskills.io)-compatible tool). Each skill is a folder under
[`skills/`](skills/) with a single-purpose `SKILL.md`, trigger evals, and optional
scripts/references — validated on every write, commit, and PR.

## Quick start

Install with the [skills CLI](https://skills.sh) — auto-detects 70+ agents
(Claude Code, Codex, Cursor, Copilot, pi, …):

```bash
npx skills add Paldom/2fa-agents                  # all detected agents
npx skills add Paldom/2fa-agents -a codex -a pi   # or target specific agents
```

Or with the [GitHub CLI](https://cli.github.com/manual/gh_skill_install) (≥ 2.90),
including version-pinned installs from releases:

```bash
gh skill install Paldom/2fa-agents
gh skill install Paldom/2fa-agents <skill> --pin <tag>
```

Or as a Claude Code plugin:

```
/plugin marketplace add Paldom/2fa-agents
/plugin install 2fa-agents@2fa-agents
```

Or copy a single skill into a project:

```bash
git clone https://github.com/Paldom/2fa-agents.git
cp -r 2fa-agents/skills/<skill-name> your-project/.claude/skills/
```

Then just describe the task — the skill activates on its description — or invoke it
explicitly with `/<skill-name>`.

## Skills

Three ways to get a code, plus custody of the secret and spending the code on a real login.

| Skill | What it does |
| --- | --- |
| [`totp-generate`](skills/totp-generate/) | Generates an RFC 6238 code offline from a seed you hold. Zero-dependency script, verified against the RFC test vectors, with window-expiry and clock-drift handling. |
| [`totp-secret-store`](skills/totp-secret-store/) | Keeps seeds and single-use backup codes in the OS keychain (or a gitignored 700 directory), and scans the repo for leaked seeds. |
| [`totp-mcp-server`](skills/totp-mcp-server/) | Self-hosted MCP server that hands out codes as a tool — two read-only tools, allowlist, rate limit, audit log, and no way to export a seed. |
| [`totp-provider-api`](skills/totp-provider-api/) | Fetches codes from 1Password, Bitwarden, Vault's TOTP engine or 2FAuth, so the seed never lands on the machine. |
| [`login-2fa-flow`](skills/login-2fa-flow/) | Drives the 2FA challenge step of an automated login — session reuse first, one fresh code, and a hard stop before lockout. |

**Which one?** *Do you hold the seed?* Yes → `totp-generate` + `totp-secret-store`.
It lives in a vault you authenticate to → `totp-provider-api`. Want any MCP client to
ask for codes → `totp-mcp-server`. Already at the prompt → `login-2fa-flow`.

They compose through one contract: a **code command** — any shell command that prints
one code to stdout and exits 0. No skill imports another, and no secret passes through
the model's context.

Setting all of this up in one pass: [docs/setup-prompt.md](docs/setup-prompt.md).

> Automating a 2FA challenge is for accounts you own or are authorised to automate. A
> seed stored beside the password it protects reduces that account to a single factor
> for whoever holds the machine — a reasonable trade for a service account, and one
> these skills state plainly rather than paper over.

## Repository structure

```
skills/                  # distributed skills, one folder per skill (SKILL.md + evals/ + scripts/)
docs/                    # skill-authoring guide, eval methodology, deployment guide
scripts/                 # deterministic validator used by hooks and CI
skills.sh.json           # skills.sh repo-page customization (groupings)
.claude/                 # agentic dev setup: hooks + bundled add-skill / publish-repo skills
.claude-plugin/          # plugin + marketplace manifests (makes this repo installable)
.local/                  # gitignored working area: sources, research, PROMPT.md (see below)
```

## Working on this repo with an agent

This repo is agent-native: canonical agent instructions live in
[AGENTS.md](AGENTS.md) (CLAUDE.md imports it), hooks validate every `SKILL.md` on
write, `make check` runs the full validator, and CI enforces the same gate on every
PR. The bundled `add-skill` skill walks the eval-first authoring workflow described
in [docs/skill-authoring.md](docs/skill-authoring.md). Maintainers drive sessions
with their own (gitignored, personal) `.local/PROMPT.md` goal prompt.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the skill-proposal
process, the authoring workflow, and the PR checklist. Please note the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Support

Questions, ideas, or something not working? Start with [SUPPORT.md](SUPPORT.md) —
bugs and skill proposals have [issue templates](../../issues/new/choose), and
security concerns go through [SECURITY.md](SECURITY.md) (never a public issue).

## License

[MIT](LICENSE) © 2026 Paldom
