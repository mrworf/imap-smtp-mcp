# Security Review Report

## Metadata

- **Project/repository:** imap-smtp-mcp
- **Git SHA:** `4f75bd5e232f515a1be2c46bb6f4b00fd509bd97`
- **Review date/time:** `2026-05-19T00:35:44Z`
- **Reviewer role:** senior application security reviewer
- **Scope reviewed:** `src/imap_smtp_mcp/`, `tests/`, `docs/`, `env.example`, `Dockerfile`, `docker-compose.yml`, and prior security-audit artifacts for orientation.
- **Commands run:** `git rev-parse HEAD`; `date -u +"%Y-%m-%dT%H:%M:%SZ"`; `git status --short`; `rg --files`; targeted `sed`/`nl` reads; targeted `rg` for security-sensitive terms; `pytest`; `python3 -m pytest`.
- **Assumptions and limitations:** Review was source-focused. No live IMAP/SMTP provider, reverse proxy, production filesystem permissions, or deployed OAuth flow was tested. Local tests could not be executed because `pytest` is not installed in this shell.

## Executive Summary

The project is in a substantially better security posture than a minimal MCP mail bridge: OAuth is scope-aware, mailbox credentials are encrypted before persistence, refresh tokens are hashed and rotated, CSRF is implemented for the credential form, write/destructive tools are gated by action flags, attachment handling is bounded, and audit logging redacts secrets by default.

I found no confirmed Critical or High vulnerabilities in the reviewed source. The main remaining risks are Medium/Low operational abuse and trust-boundary issues: sender identity is accepted from the OAuth form without binding it to the SMTP account or configured domain, public Dynamic Client Registration can grow persistent state without a durable quota, and the threaded HTTP server shares one SQLite connection without store-level locking. These are worth fixing before broad multi-user or internet-facing deployment.

## Scope and Methodology

I reviewed the MCP HTTP entry points, OAuth registration/authorization/token flow, credential vault and SQLite store, tool scope enforcement, send/read/write services, adapter TLS behavior, audit logging, attachment controls, deployment defaults, and relevant regression tests. I also checked docs to see whether operational mitigations are documented and whether risky debug modes are called out.

## Threat Model

- **Exposed interfaces:** HTTP `GET /healthz`, `GET /readyz`, OAuth metadata endpoints, `POST /oauth/register`, `GET/POST /oauth/authorize`, `POST /oauth/token`, and MCP JSON-RPC over `/sse`.
- **Sensitive assets:** IMAP passwords, SMTP passwords, encrypted credential sessions, bearer tokens, refresh tokens, email bodies, attachment bytes, folder/message metadata, audit logs, OAuth signing/cookie/encryption keys.
- **Trust boundaries:** browser/user to OAuth server, MCP host/model/client to mail tools, OAuth bearer token to credential vault, MCP server to IMAP/SMTP backends, reverse proxy to app-local rate limiting, local filesystem to SQLite/audit storage.
- **Likely attacker profiles:** unauthenticated internet client hitting OAuth endpoints, authorized connector client with scoped token, malicious or compromised OAuth client redirect, mailbox user abusing send capability, network attacker if deployment disables HTTPS, local host user with access to runtime storage.

## Findings Summary

| ID | Severity | CVSS | Confidence | Title | Status |
|----|----------|------|------------|-------|--------|
| SEC-001 | Medium | 4.3 | Confirmed code path, deployment-dependent impact | Sender identity is not bound to SMTP account or configured domain | Open |
| SEC-002 | Medium | 5.3 | High | Public Dynamic Client Registration can grow persistent OAuth state without durable quotas | Open |
| SEC-003 | Low | 3.7 | High | Shared SQLite connection is used across threaded HTTP handlers without store-level serialization | Open |

## Detailed Findings

### SEC-001: Sender identity is not bound to SMTP account or configured domain

- **Severity:** Medium
- **CVSS v3.1:** 4.3 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
- **Confidence:** Confirmed code path, deployment-dependent impact
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/oauth.py:480`, `src/imap_smtp_mcp/tool_controller.py:436`, `src/imap_smtp_mcp/send_tools.py:36`, `src/imap_smtp_mcp/config.py:358`

#### Evidence

`OAuthService.authorize_with_credentials()` requires a syntactically valid `sender_email`, but does not require it to match `smtp_username`, `SMTP_FROM_DOMAIN`, or an SMTP-provider-verified identity. It stores the selected value in the encrypted credential session (`oauth.py:494-511`). `MailToolController` correctly ignores caller-supplied `from_address` and sends with the captured session sender (`tool_controller.py:436-457`), and `SendEmailService` places that address directly into the message `From` header (`send_tools.py:66-70`). `SMTP_FROM_DOMAIN` is parsed as optional config and currently used for UI suggestion, not enforcement (`config.py:358-362`).

#### Preconditions

The attacker needs to complete OAuth authorization with IMAP/SMTP credentials and receive `mail:send`. Impact requires an SMTP backend that permits sending with arbitrary or weakly checked `From` addresses.

#### Exploit Scenario

A mailbox user authorizes the connector with valid credentials but enters `finance@example.org` or another misleading sender address. If the SMTP backend accepts it, subsequent `send_email` calls send mail with that captured identity. Tool callers cannot override the identity after authorization, which is good, but the authorization-time identity remains an unverified trust decision.

#### Safe PoC / Validation

In a local unit test, call `authorize_with_credentials()` with `smtp_username="alice@example.com"` and `sender_email="ceo@example.org"`, then exchange the code and inspect the decrypted `MailCredentials.sender_email`. The current code accepts the mismatch if the email syntax is valid and IMAP verification succeeds.

#### Impact

Integrity impact is bounded to outbound mail identity. This can enable spoofing, social engineering, or compliance problems in deployments where the SMTP server does not enforce sender ownership.

#### Remediation

Add a sender policy. A conservative default would require `sender_email == smtp_username` when `smtp_username` is an email address, or require `sender_email` to be under `SMTP_FROM_DOMAIN` when configured. For stronger assurance, verify the SMTP login and provider-permitted sender identity during authorization or before first send. Preserve the current no-caller-override behavior.

#### Verification

Add positive tests for matching sender identity and negative tests for mismatched sender/domain. Include a test proving `SMTP_FROM_DOMAIN` is enforcement, not only autofill, if that policy is chosen.

### SEC-002: Public Dynamic Client Registration can grow persistent OAuth state without durable quotas

- **Severity:** Medium
- **CVSS v3.1:** 5.3 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/server.py:115`, `src/imap_smtp_mcp/server.py:326`, `src/imap_smtp_mcp/oauth.py:420`, `src/imap_smtp_mcp/oauth.py:256`

#### Evidence

`POST /oauth/register` is unauthenticated by design and calls `OAuthService.register_client()` after an app-local rate-limit check (`server.py:115-122`). The rate limiter is in memory and keyed primarily by `self.client_address[0]` (`server.py:326-355`), so limits reset on restart and can be distorted behind a reverse proxy unless edge controls are deployed. Successful registration persists every generated client in `oauth_clients` (`oauth.py:256-261`, `oauth.py:420-446`). I did not find a maximum client count, registration TTL, stale-client cleanup, or persistent quota.

#### Preconditions

The OAuth registration endpoint is reachable by unauthenticated clients. Redirect allowlisting must permit at least one redirect URI, as expected for normal operation.

#### Exploit Scenario

An internet client repeatedly registers allowed redirect URIs over time or from distributed addresses. Each successful request adds durable SQLite rows. Local request-size limits and per-IP rate limits slow the attack, but persistent growth can still consume disk or operational capacity, especially when reverse-proxy limits are absent or misconfigured.

#### Safe PoC / Validation

Against a local dev server with an allowed redirect pattern, repeatedly `POST /oauth/register` with the same allowed `redirect_uris` and varying or default `client_name`, then query `SELECT COUNT(*) FROM oauth_clients`. The count grows and does not expire automatically.

#### Impact

Availability and operations risk: disk growth, slower store operations over time, and cleanup burden. Confidentiality and integrity impact are not direct because redirect URI validation and PKCE remain enforced.

#### Remediation

Add one or more durable controls: maximum total registered clients, per-redirect/client-name quotas, stale-client cleanup for clients with no active sessions, or an operator-configurable registration allow mode. Keep the documented reverse-proxy limits, but do not make them the only durable mitigation.

#### Verification

Add tests that registration fails once the configured persistent client cap is reached and that cleanup removes stale clients without deleting active sessions.

### SEC-003: Shared SQLite connection is used across threaded HTTP handlers without store-level serialization

- **Severity:** Low
- **CVSS v3.1:** 3.7 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/server.py:44`, `src/imap_smtp_mcp/oauth.py:203`

#### Evidence

The server subclasses `ThreadingHTTPServer` (`server.py:44-63`). `OAuthService` creates a single `OAuthStore`, and `OAuthStore` creates one SQLite connection with `check_same_thread=False` (`oauth.py:203-209`). Store methods perform reads/writes/commits directly without a store-level lock (`oauth.py:256-376`). The authorization-code reuse path uses an atomic `UPDATE ... WHERE used = 0`, which is good, but the shared connection itself is still concurrently accessed.

#### Preconditions

Concurrent OAuth traffic reaches the same server process.

#### Exploit Scenario

An unauthenticated client sends bursts of registration/token/authorize requests while legitimate users are authorizing. Depending on SQLite/Python scheduling, concurrent use of one connection can produce transient `sqlite3` errors or handler failures, causing authentication availability problems.

#### Safe PoC / Validation

Run a local threaded stress test that sends concurrent `POST /oauth/register` and `POST /oauth/token` requests against one process while capturing stderr and response failures. This is non-destructive if run against a temporary `OAUTH_STORE_PATH`.

#### Impact

Bounded availability risk for OAuth flows. I did not find evidence of credential disclosure or authorization bypass from this issue.

#### Remediation

Use one connection per request/thread, or wrap all SQLite operations in a `threading.RLock` inside `OAuthStore`. Consider WAL mode and a bounded busy timeout for better concurrent read/write behavior.

#### Verification

Add a concurrent registration/token stress test using a temporary store and assert no uncaught exceptions or malformed responses.

## Exploit Chains

No high-impact exploit chain was confirmed. The most realistic chain is operational: SEC-002 can increase OAuth store size and SEC-003 can make concurrent OAuth store access less reliable, together raising availability risk for authorization and token exchange. This does not currently change confidentiality or integrity impact.

## Hardening Recommendations

- Add explicit runtime JSON Schema validation before dispatching `tools/call`. The services do substantial validation, but several tool schemas omit `additionalProperties: False`, and missing required arguments can currently become generic backend errors instead of deterministic invalid-input responses.
- Consider validating JWT header fields (`alg == HS256`, `typ == JWT`) before accepting tokens. The HMAC signature prevents practical `alg=none` forgery, so this is standards hardening rather than an active bypass.
- Keep `MCP_DEBUG_UNREDACTED_LOGS=false` in production. The code sanitizes password/token/key/content-base64 fields, but debug mode intentionally logs email subjects, bodies, arguments, results, and tracebacks.
- Add edge rate limits for `POST /oauth/token` as docs recommend. Token guessing is not practical due to entropy and PKCE, but unauthenticated token requests can still generate store lookups and audit noise.
- Consider suppressing or customizing `BaseHTTPRequestHandler` request-line logging for OAuth authorize URLs to avoid logging `state`, `client_id`, and `code_challenge` in stderr/proxy logs.

## Positive Security Observations

- OAuth bearer checks are required for `tools/list` and `tools/call`, and tool calls map to read/send/write scopes (`server.py:214-248`, `tool_controller.py:20-41`).
- Credential storage uses Fernet encryption, and refresh tokens are stored as keyed hashes rather than plaintext (`oauth.py:172-199`, `oauth.py:343-370`).
- Authorization code exchange enforces redirect URI, client ID, PKCE S256, expiration, and one-time use; reuse revokes the credential session (`oauth.py:536-560` and following code).
- OAuth redirect registration requires HTTPS, no userinfo/fragments/control characters, and a configured allowlist (`oauth.py:420-430`, `oauth.py:674-685`).
- The authorize form has signed, query-bound CSRF cookies plus hidden form token validation (`server.py:157-165`, `server.py:693-716`).
- Production config fails fast on weak OAuth signing/cookie secrets and missing credential encryption key unless the explicit dev escape hatch is set (`config.py:272-280`).
- IMAP TLS verification cannot be disabled through config, and SMTP/IMAP adapters pass TLS contexts and timeouts by keyword (`config.py:329-331`, `imap_adapter.py:70-81`, `smtp_adapter.py:57-75`).
- Write/destructive mail operations are disabled by default and enforced before adapter calls (`config.py:340-355`, `write_tools.py:48-154`).
- Attachment filenames, MIME types, decoded sizes, counts, and base64 payloads are bounded/validated for send and retrieval paths (`attachments.py`, `send_tools.py:96-119`, `read_tools.py:512-545`).
- Audit logging hashes usernames into filenames, prevents path escape, rotates logs, and redacts secret-like fields by default (`audit.py:45-124`).
- Docker deployment runs as a non-root user, read-only filesystem, no-new-privileges, and drops Linux capabilities (`Dockerfile`, `docker-compose.yml:8-27`).

## Assumptions and Limitations

Tests were not run because this shell has no `pytest` command and `python3 -m pytest` reports `No module named pytest`. I did not install dependencies because the request was for an audit report, not environment setup. Manual mailbox verification, live SMTP sender policy, reverse-proxy behavior, and production file permissions were not validated.

## Appendix

### Command Results

- `git rev-parse HEAD`: `4f75bd5e232f515a1be2c46bb6f4b00fd509bd97`
- `date -u +"%Y-%m-%dT%H:%M:%SZ"`: `2026-05-19T00:35:44Z`
- `git status --short`: no output, working tree clean at metadata collection time.
- `pytest`: failed, command not found.
- `python3 -m pytest`: failed, `No module named pytest`.
