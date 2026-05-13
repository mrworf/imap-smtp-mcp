# IMAP/SMTP MCP Server Implementation Plan

## Current state
The repository now contains the first implementation of a Docker-hosted IMAP/SMTP MCP server with built-in OAuth support. Earlier milestone labels that described the project as complete were inaccurate: the previous codebase had adapters and service classes, but `python -m imap_smtp_mcp.server` did not expose a usable MCP endpoint.

## Goal
Run a self-contained MCP endpoint that ChatGPT can connect to over a public HTTPS URL, authorize with OAuth 2.1, and use to perform IMAP/SMTP actions through separately supplied IMAP and SMTP credentials.

## Milestones

### Milestone 1 — Truthful roadmap reset
- Replace stale completion claims with the real roadmap and implementation status.
- Keep future work bounded by the milestone being requested.

### Milestone 2 — Dependency and test baseline
- Use Python 3.12 and `pytest`.
- Keep runtime dependencies small; `cryptography` is required for encrypted credential sessions.
- All previous and current milestone tests must pass before moving forward.

### Milestone 3 — OAuth and proxy-aware configuration
- Parse public base URL, issuer, audience, token TTLs, signing/encryption secrets, server host/port, and reverse-proxy settings.
- Require HTTPS public URLs for production deployments.
- Allow internal HTTP behind a TLS-terminating reverse proxy.

### Milestone 4 — OAuth metadata and Dynamic Client Registration
- Expose:
  - `GET /.well-known/oauth-protected-resource`
  - `GET /.well-known/oauth-authorization-server`
  - `POST /oauth/register`
- Emit public HTTPS URLs derived from `MCP_PUBLIC_BASE_URL`.

### Milestone 5 — Authorization code + PKCE
- Expose `GET/POST /oauth/authorize`.
- Collect separate IMAP and SMTP credentials.
- Verify IMAP login before issuing an authorization code.
- Bind authorization code to client, redirect URI, PKCE challenge, scopes, resource, and encrypted credential session.

### Milestone 6 — Token endpoint and persistent credential vault
- Expose `POST /oauth/token`.
- Exchange authorization codes with PKCE verification.
- Issue signed bearer tokens containing no mailbox passwords.
- Store OAuth clients, authorization codes, credential sessions, and hashed refresh tokens in SQLite at `OAUTH_STORE_PATH`.
- Support refresh-token rotation for small self-hosted deployments.

### Milestone 7 — Bearer auth for MCP requests
- Validate bearer token signature, issuer, audience, expiry, scopes, and credential session on every MCP request.
- Return OAuth `WWW-Authenticate` challenges for unauthenticated requests.

### Milestone 8 — Streamable HTTP MCP endpoint
- Expose runtime endpoints:
  - `GET /healthz`
  - `GET /readyz`
  - MCP JSON-RPC over `/sse`
- Support `initialize`, `tools/list`, and `tools/call`.
- Document that `/sse` is Streamable HTTP-compatible and not strict legacy long-lived SSE; native stdio is out of scope.

### Milestone 9 — Authenticated tool controller
- Map OAuth sessions to IMAP/SMTP credentials.
- Never accept mailbox credentials as tool arguments.
- Enforce action flags before adapter calls.

### Milestone 10 — Tool response and error contract
- Normalize tool outputs to JSON-serializable dictionaries/lists.
- Return stable errors for auth, invalid input, disabled actions, not found, and backend failures.

### Milestone 11 — Audit and redaction
- Audit OAuth and MCP events.
- Never log passwords, bearer tokens, raw auth headers, or message bodies.

### Milestone 12 — Docker and reverse proxy deployment
- Run the server as the container CMD.
- Support nginx/Caddy/Traefik TLS termination with internal HTTP.
- Support direct internal HTTPS via `MCP_INTERNAL_HTTPS`, `MCP_TLS_CERT_FILE`, and `MCP_TLS_KEY_FILE`.
- Provide healthchecks and sample deployment docs.

### Milestone 13 — ChatGPT setup docs
- Document DCR, authorization-code + PKCE, scopes, redirect handling, and reverse-proxy requirements.

### Milestone 14 — Manual compatibility suite
- Launch the server on a temporary port by default.
- Drive OAuth and real MCP calls through the endpoint.
- Keep destructive real-mailbox tests manual-only.

### Milestone 15 — End-to-end mailbox gate
- Verify OAuth plus all mail tools against a dedicated real mailbox.
- Include a reverse-proxy smoke path.

### Milestone 16 — Final quality gate
- Run all accumulated tests, lint, and type checks where available.
- If a test failure reveals a future-useful lesson, add it to `AGENTS.md`.

## Definition of done
- ChatGPT can connect to the public `/sse` URL, register through DCR, authorize via OAuth, and call tools with a bearer token.
- IMAP login is the authorization source of truth.
- IMAP and SMTP credentials remain separate.
- Public URLs are HTTPS; internal proxy-to-app transport may be HTTP.
- OAuth state survives container restarts via SQLite-backed persistence.
- Secrets and message bodies are never logged.
- Positive and negative tests cover every new feature.
