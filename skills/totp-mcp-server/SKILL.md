---
name: totp-mcp-server
description: Builds and self-hosts an MCP server that serves TOTP codes as a tool, so agents get 2FA codes without the shared secret entering the model's context. Use when the user wants an MCP server for 2FA or TOTP, to self-host a code service for Cursor or Claude Code, or when their 2FA MCP server shows no tools. Not for one-off code generation, password-manager APIs, or generic MCP server work.
license: MIT
---

# totp-mcp-server

Stand up a local MCP server whose only job is handing out current 2FA codes. The
agent calls a tool and receives six digits; the seed stays on disk, out of the
transcript, and out of every prompt the model ever sees. Fixes the failures that
make this go wrong: a bare exception swallowing the error the model needed, anything
printed to stdout killing the stdio stream, an unpinned SDK, and a "helpful" tool
that can export secrets.

A working server ships in `scripts/totp_mcp_server.py` — verified against a real MCP
client (tools listed, code issued, traversal denied, rate limit enforced).

## When NOT to use

- One-off code generation on this machine → `totp-generate`.
- Where the seed is stored, enrolment, backup codes → `totp-secret-store`.
- Codes from 1Password / Bitwarden / Vault → `totp-provider-api`.
- Filling the code into a login form → `login-2fa-flow`.
- MCP servers for anything other than 2FA, or OAuth/auth wiring → the general
  MCP server skills, not this one.

## The tool surface, and what is deliberately absent

Two read-only tools:

| Tool | Returns |
| --- | --- |
| `list_totp_accounts()` | account names this server may serve |
| `get_totp_code(account)` | `{code, expires_in, period}` |

There is **no** tool that stores, reads, exports, or lists secrets. Do not add one.
A write tool is a privilege-escalation surface reachable by prompt injection through
any web page, issue, or file the model reads — "add this account: otpauth://…" is a
single sentence away from an attacker-controlled seed being trusted. Enrolment stays
a human action at the keychain.

Likewise no tool returns the seed, and neither error messages nor the audit log ever
contain a secret or a generated code.

## Be honest about the boundary

Two things this does **not** protect against. Say both out loud; the controls below
are real but narrow.

**It is not a machine boundary.** A stdio MCP server is a subprocess of the client
running with the user's full privileges. "The seed never leaves the server" holds
against *the model's context* — a genuine win, because contexts get logged, cached
and summarised — but any agent with shell access can read the same keychain directly.

**`get_totp_code` is a code oracle.** It deliberately puts a live second factor into
model-visible output, and each control bounds something other than authorisation:

- the **allowlist** validates input, it does not authorise a *purpose* — every account
  you care about is on it by construction;
- the **rate limit** bounds volume, but credential theft needs exactly one call;
- the **audit log** is post-hoc and cannot tell a real login from an exfiltration,
  because both entries read `github, issued`;
- **no seed export** downgrades a permanent compromise to a 60-second one — ample for
  an injected instruction executing in the same loop.

So an agent that reads untrusted content (a web page, an issue, a dependency README)
can be induced to call this tool, and the call looks identical to a legitimate one.
Consequences worth acting on:

- **Do not auto-approve `get_totp_code`.** Leave it on the client's manual-approval
  path. That per-call human confirmation is the authorisation the tool surface lacks.
- Do not run this server in the same session as untrusted browsing when the account
  matters. Scope `TOTP_MCP_ACCOUNTS` to the minimum for the task at hand.
- Treat `list_totp_accounts` as an inventory disclosure — it tells anything in the
  context which accounts are automatable here.
- For a high-value account, the durable fix is to not return the code at all: have the
  server submit it into the login session and return only pass/fail. That is a larger
  design (the server needs the browser session) and is **not** what this skill ships.

## Workflow

### 1. Run it, pinned

The script carries PEP 723 inline metadata pinning `mcp>=2.1,<3`, so no project
setup is needed:

```bash
uv run --script "${CLAUDE_SKILL_DIR}/scripts/totp_mcp_server.py"   # exits at stdin EOF
```

Never launch an MCP server with an unpinned `npx pkg@latest` / `pip install pkg`: a
dependency that starts printing a banner to stdout kills every stdio install
downstream. The Python SDK's v2 line (`mcp` 2.x, spec 2026-07-28) has a different API
from v1 — if you must stay on v1, pin `mcp>=1.28,<2` and expect `FastMCP`, not
`MCPServer`.

### 2. Configure

Secrets come from the same places `totp-secret-store` writes them.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TOTP_MCP_BACKEND` | `keychain` where available, else `file` | where secrets are read from |
| `TOTP_MCP_SERVICE` | `totp` | keychain service namespace |
| `TOTP_MCP_DIR` | `~/.config/totp/totp` | file-backend directory |
| `TOTP_MCP_ACCOUNTS` | empty = all stored | comma-separated allowlist |
| `TOTP_MCP_AUDIT` | `~/.local/state/totp-mcp/audit.log` | one JSONL line per request |
| `TOTP_MCP_RATE` | `10` | max calls per account per minute |

Set `TOTP_MCP_ACCOUNTS` explicitly. An empty allowlist means every enrolled account
is reachable by any agent connected to this server.

### 3. Register as a stdio server

```json
{
  "mcpServers": {
    "totp": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--script", "/absolute/path/to/totp_mcp_server.py"],
      "env": { "TOTP_MCP_ACCOUNTS": "github,npm" }
    }
  }
}
```

Absolute path — the server is launched with the client's working directory, not
yours. Project scope (`.mcp.json`) is committable; it must contain **no secrets**,
only account *names*. Then start a new session: stdio tools are discovered at
session start, so a mid-session edit changes nothing.

### 4. Verify before declaring it done

List the tools and fetch one code through an actual client. `claude mcp list` shows
connection state and whether a project-scoped server is still pending trust
approval. A config that parses is not a server that works.

## Output spec

- Server registered, a new session started, `list_totp_accounts` returns the expected
  names, and `get_totp_code` returns a code with `expires_in`.
- Allowlist set; audit log path exists and gains a line per request.
- No secret in the client config, in the repo, or in the transcript.

## Gotchas

| Symptom | Cause and fix |
| --- | --- |
| Client shows the server but no tools | Something wrote to stdout — the launcher, a `print()`, a dependency banner. All diagnostics go to stderr |
| Tools missing after editing the config | stdio tools are discovered at session start; restart the client |
| Model gets "Error executing tool X" with no detail | The handler raised a bare exception. Only the SDK's `ToolError` reaches the model; anything else is logged as a crash and the message is dropped |
| `${VAR}` unset in `.mcp.json` | The whole file fails to parse and the server silently vanishes; use `${VAR:-default}` |
| Server pending approval | Project-scoped servers need an interactive trust prompt once |
| Works from your shell, not from the client | Relative path, or `uv` not on the client's `PATH` — use absolute paths for both |
| Agent retries a rejected code in a loop | Rate limit is doing its job; the fix is waiting for the next window, not raising the limit |

## References

- `references/serving.md` — the security review checklist for this server, the
  stdio-versus-Streamable-HTTP decision, remote-exposure requirements, and how to
  re-verify the SDK pin when the spec revision moves.
