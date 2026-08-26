# Serving TOTP over MCP: review checklist, transports, and version drift

**Contents:** [Security checklist](#security-checklist-run-before-registering) ·
[Threats specific to a 2FA server](#threats-specific-to-a-2fa-server) ·
[stdio vs Streamable HTTP](#stdio-vs-streamable-http) ·
[Exposing it beyond one machine](#exposing-it-beyond-one-machine) ·
[Spec and SDK drift](#spec-and-sdk-drift) · [Debugging stdio](#debugging-stdio) ·
[Sources](#sources)

## Security checklist (run before registering)

- [ ] No tool stores, reads, exports, or lists a **secret** — only account names.
- [ ] The `account` argument is validated against the allowlist **before** any
      secret is touched. This is also what stops `../../etc/passwd` reaching the
      file backend.
- [ ] `TOTP_MCP_ACCOUNTS` is set. Empty means every enrolled account is reachable.
- [ ] Error messages contain no secret, no code, and a concrete recovery hint.
- [ ] The audit log records account + outcome, never the secret and never the code.
- [ ] Rate limit is on. A code is valid for one window; repeat calls cannot help and
      only burn the issuer's attempt budget.
- [ ] The SDK version is pinned, and the launcher writes nothing to stdout.
- [ ] The client config contains account names only — it is committable.

## Threats specific to a 2FA server

The general MCP attack classes apply, but three matter disproportionately here.

**Prompt injection reaching the tool.** The model calling `get_totp_code` may be
acting on text it read from a web page, an issue, or a dependency's README. Treat
every tool argument as attacker-controlled. This is why enrolment is not a tool and
why the allowlist is enforced in code — a guardrail that survives the system prompt
being deleted is a real guardrail; one written in a tool description is not.

**Tool poisoning and rug pulls.** Tool descriptions are model-facing instructions the
user typically never reads. Keep this server's descriptions factual and short, and
review any diff to them as you would a diff to an auth check. For third-party 2FA
servers: pin the version and re-review on upgrade.

**Silent code harvesting.** A code is only useful inside its window, but a server
that hands out codes on demand with no record gives an attacker who compromises the
agent an unbounded supply. The audit log is the detection control — check it after
any suspicious session; a burst of `issued` events you did not initiate means the
seed must be rotated at the issuer.

The log is itself sensitive: it records which accounts you hold and when each is used.
That is a usage-pattern disclosure even though it contains no secret and no code. Keep
it in a mode-700 directory, think before shipping it to a shared log aggregator, and
never commit it.

## stdio vs Streamable HTTP

| | stdio | Streamable HTTP |
| --- | --- | --- |
| Deployment | subprocess of one client on one machine | a service, potentially multi-client |
| Auth | none — inherits the user's privileges | required; unauthenticated means anyone reachable gets codes |
| Right for 2FA | almost always | only with real token auth and a network boundary |

MCP defines exactly these two transports. Choosing between them is a deployment
decision, not a flag: moving to HTTP adds authentication, network exposure, and an
operational surface. For a personal 2FA server, stdio is the correct answer and
"my other laptop needs it too" is better solved with an SSH tunnel than with a port.

## Exposing it beyond one machine

If it must be remote, all of these, not some:

1. Bind `127.0.0.1` and reach it through an SSH tunnel or a mesh VPN. Do not bind
   `0.0.0.0`.
2. Require a bearer token; validate the token's **audience** so a token minted for
   another service cannot be replayed here.
3. Validate the `Origin` header on browser-reachable endpoints (DNS-rebinding
   defence).
4. Rate-limit per identity, not just per account, and alert on anomalies.
5. Log every issue event with the caller identity, to an append-only store.

An unauthenticated remote endpoint that returns 2FA codes is a credential-vending
service for anyone who can route to it. There is no low-stakes version of this.

## Spec and SDK drift

Verified 2026-08-26:

| | Value |
| --- | --- |
| Current spec revision | `2026-07-28` |
| Python SDK, current line | `mcp` 2.x (`MCPServer`, `@mcp.tool()`, `run("stdio")`), Python ≥ 3.10 |
| Python SDK, previous line | `mcp` 1.x on the `v1.x` branch — `FastMCP`; pin `mcp>=1.28,<2` |
| TypeScript, current line | `@modelcontextprotocol/server` 2.x (v1 was `@modelcontextprotocol/sdk`) |

The 2026-07-28 revision made the protocol **stateless**: the mandatory
`initialize`/`initialized` handshake is gone (replaced by an optional
`server/discover`), and `Mcp-Session-Id` is removed. The SDKs negotiate with older
clients for you — which is the main reason to use an SDK rather than hand-rolling
JSON-RPC framing. Roots, Sampling, Logging, and the legacy HTTP+SSE transport are
deprecated with a 12-month offramp.

Re-check <https://modelcontextprotocol.io/specification> and the SDK release notes
if months have passed; a major SDK line changes class names, not just behaviour.

## Debugging stdio

The framing rules are strict and the failure is silent:

- One JSON-RPC message per line, no embedded newlines, UTF-8.
- The server **MUST NOT** write anything to stdout that is not an MCP message —
  a stray `print()`, a progress bar, or a dependency banner ends the session.
- stderr is free for logging; clients may capture or ignore it.
- Servers should exit when stdin reaches EOF. That is the portable shutdown signal.

To see what is actually on the wire, run the server directly and pipe a request in,
or use the MCP Inspector. If the client shows the server but zero tools, check
stdout hygiene first and session restart second.

## Sources

- MCP specification — <https://modelcontextprotocol.io/specification/2026-07-28>
- stdio transport binding — <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio>
- 2026-07-28 release notes — <https://blog.modelcontextprotocol.io/posts/2026-07-28/>
- Python SDK — <https://py.sdk.modelcontextprotocol.io/> · <https://github.com/modelcontextprotocol/python-sdk>
- Claude Code MCP configuration — <https://code.claude.com/docs/en/mcp-quickstart>
