# Security Review Report

## Metadata

- **Project/repository:** `imap-smtp-mcp`
- **Git SHA:** `8683d39967c7d12e7946ccc4598e64c67ba91eb2`
- **Review date/time:** `2026-05-20T06:40:09Z`
- **Reviewer role:** senior application security reviewer
- **Scope reviewed:** `src/imap_smtp_mcp/`, `tests/`, `docs/`, `.github/workflows/ci.yml`, `pyproject.toml`, `env.example`, `Dockerfile`, `docker-compose.yml`, and prior reports in `security-audits/`.
- **Commands run:** `git rev-parse HEAD`; `date -u +"%Y-%m-%dT%H:%M:%SZ"`; `git status --short`; `rg --files`; targeted `rg`, `sed`, and `nl` reads; `pytest -q`; `python3 -m pytest -q`; `.venv/bin/python -m pytest -q`; escalated `.venv/bin/python -m pytest -q` for loopback-bound endpoint tests.
- **External references consulted:** PyPI `cryptography` project page, PyCA/GitHub advisories `GHSA-p423-j2cm-9vmq` and `GHSA-m959-cc7f-wv43`.
- **Assumptions and limitations:** This was a source-focused review. I did not test against a live IMAP/SMTP provider, production reverse proxy, deployed filesystem permissions, or real ChatGPT OAuth integration. Dependency advisory checks were limited to the direct runtime dependency visible in `pyproject.toml`.

## Executive Summary

The implementation has strong baseline controls for a self-hosted mail MCP server: OAuth + PKCE is implemented, bearer tokens are checked before tool calls, mailbox credentials are encrypted in SQLite, refresh tokens are hashed and rotated, IMAP/SMTP credentials remain separate, action flags are enforced before adapter calls, dangerous attachments are blocked by policy, and the Docker runtime is meaningfully hardened.

I did not find a confirmed unauthenticated remote path to mailbox credential disclosure or cross-user mailbox access. The most important remaining risks are deployment and abuse edges: weak OAuth signing guardrails combine poorly with bearer scopes being trusted only from the JWT, Dynamic Client Registration still has no durable client quota, direct HTTP exposure lacks request read timeouts, sender identity is still accepted at OAuth time without SMTP/domain binding, and default failure audit metadata can persist sensitive search terms.

## Scope and Methodology

I reviewed the HTTP entry points, OAuth service and SQLite store, JWT signing and verification, credential vault, read/send/write tool dispatch, action flag enforcement, audit logging, attachment handling, deployment defaults, CI and dependency manifests, and relevant regression tests. I also compared current code against prior audit findings to distinguish fixed issues from risks still present.

## Threat Model

- **Exposed interfaces:** HTTP health/ready endpoints, OAuth metadata, `POST /oauth/register`, `GET/POST /oauth/authorize`, `POST /oauth/token`, and MCP JSON-RPC over `/sse`.
- **Sensitive assets:** IMAP passwords, SMTP passwords, encrypted credential sessions, bearer tokens, refresh tokens, OAuth signing/cookie/encryption keys, email bodies, attachments, mailbox metadata, and audit logs.
- **Trust boundaries:** browser/user to OAuth form, remote MCP host/model to tool server, bearer token to credential vault, MCP server to IMAP/SMTP providers, reverse proxy to app-local rate limiting, and local runtime storage to operators/log readers.
- **Likely attacker profiles:** unauthenticated internet client, authorized low-scope mailbox user, malicious or compromised MCP/OAuth client, network client attempting resource exhaustion, local log reader, and supply-chain actor.

## Findings Summary

| ID | Severity | CVSS | Confidence | Title | Status |
|----|----------|------|------------|-------|--------|
| SEC-001 | Medium | 6.4 | High | Weak OAuth signing guardrails plus missing session-scope check can allow token scope/TTL escalation | Open |
| SEC-002 | Medium | 5.3 | Confirmed | Dynamic Client Registration persists clients without a durable quota | Open |
| SEC-003 | Medium | 5.3 | High | Direct HTTP exposure has no request read timeout | Open |
| SEC-004 | Medium | 4.3 | Confirmed, deployment-dependent impact | Sender identity is not bound to SMTP account or configured domain | Open |
| SEC-005 | Low | 3.0 | Confirmed | Failure audit metadata can log sensitive search terms outside debug mode | Open |

## Detailed Findings

### SEC-001: Weak OAuth signing guardrails plus missing session-scope check can allow token scope/TTL escalation

- **Severity:** Medium
- **CVSS v3.1:** 6.4 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `env.example`, `docker-compose.yml`, `src/imap_smtp_mcp/config.py`, `src/imap_smtp_mcp/oauth.py`

#### Evidence

`env.example` contains public placeholder values for `OAUTH_SIGNING_KEY` and `OAUTH_COOKIE_SECRET` that satisfy the current length-only production validation (`env.example:20-21`, `config.py:250-251`). `docker-compose.yml` loads `./env.example` directly (`docker-compose.yml:6-7`), so an operator who replaces only endpoint values and the Fernet key can still run with known signing/cookie secrets.

Bearer authentication verifies the JWT signature and required scopes, then only checks that the token `sid` exists and that `sub` matches the stored session (`oauth.py:657-673`). It does not verify that `claims.scopes` are a subset of `CredentialSession.scopes`, even though the session scopes are persisted at authorization time (`oauth.py:525-531`) and refresh-token scopes are persisted/rotated (`oauth.py:625-645`).

#### Preconditions

The practical exploit requires a weak, known, or leaked `OAUTH_SIGNING_KEY`, plus a valid existing credential session ID. The most realistic path is accidental production use of `OAUTH_DEV_INSECURE_SECRETS=true` or the placeholder signing key pattern. The attacker generally needs at least one authorized session for their mailbox.

#### Exploit Scenario

An operator deploys with a known placeholder or dev signing key while intending to restrict OAuth scopes, for example issuing only `mail:read`. An authorized user can read their own access token, learn their `sid` and `sub`, and mint a new JWT with additional scopes such as `mail:send` or `mail:write` and a longer expiration. Because `authenticate_bearer()` trusts scopes from the signed token and does not compare them to the stored session scopes, tool scope checks accept the forged broader token if action flags allow the tool.

#### Safe PoC / Validation

In a local unit test, create a `CredentialSession` with `scopes=("mail:read",)`, issue a token with the same `session_id` and `subject` but `scopes=("mail:read","mail:send")` using the configured signer, then call `authenticate_bearer(..., required_scopes=("mail:send",))`. Current code accepts the token and returns credentials. This validation is local and does not target any real mailbox.

#### Impact

The direct impact is scope and token-lifetime escalation for sessions protected by weak/known signing keys. Depending on enabled action flags, this can mean unauthorized sending, mailbox mutation, or destructive operations for the affected session. Strong random signing keys materially reduce exploitability, but the stored session scope should still be enforced as a server-side backstop.

#### CVSS Rationale

`AV:N` because exploitation happens through bearer-protected network tools, `AC:H` because weak/known signing key deployment is a required precondition, `PR:L` because an existing authorized session is needed, `UI:N`, `S:U`, with low confidentiality and availability impact and potentially high integrity impact when send/write/destructive actions are enabled.

#### Remediation

Reject known placeholders and `OAUTH_DEV_INSECURE_SECRETS=true` for non-local public URLs at startup. Validate that `OAUTH_ENCRYPTION_KEY` is a syntactically valid Fernet key during config load. In `authenticate_bearer()`, after loading the session, reject any token whose scopes are not a subset of `session.scopes`.

#### Verification

Add negative tests for placeholder secrets, dev insecure mode with non-local `MCP_PUBLIC_BASE_URL`, invalid Fernet keys, and a forged broader-scope token against a narrower persisted session.

### SEC-002: Dynamic Client Registration persists clients without a durable quota

- **Severity:** Medium
- **CVSS v3.1:** 5.3 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/server.py`, `src/imap_smtp_mcp/oauth.py`

#### Evidence

`POST /oauth/register` is unauthenticated by design and only uses an in-memory rate-limit check before calling `OAuthService.register_client()` (`server.py:115-122`). Registration validates redirect URIs and then creates a fresh random `client_id`; `OAuthStore.save_client()` inserts every client into `oauth_clients` with no TTL, total count cap, or stale-client cleanup (`oauth.py:256-261`, `oauth.py:432-446`). The current in-memory limiter has a bucket cap (`server.py:349-360`), but that does not bound durable rows already written.

#### Preconditions

The OAuth registration endpoint is reachable, and the deployment has a configured redirect allowlist that accepts at least one URI.

#### Exploit Scenario

An unauthenticated client repeatedly registers the same allowed redirect URI over time or from distributed addresses. Each success persists another client row. Local rate limits slow the attack but reset on restart and do not provide a durable storage quota.

#### Safe PoC / Validation

Against a local test server and temporary SQLite store, repeatedly submit valid `POST /oauth/register` requests with the configured allowed redirect URI, then query `SELECT COUNT(*) FROM oauth_clients`. The count increases and survives process restart.

#### Impact

Availability and operations impact: disk growth, cleanup burden, and potential store slowdown. Redirect allowlisting and PKCE still prevent this from becoming a direct token theft issue.

#### CVSS Rationale

Unauthenticated network reachability and low attack complexity justify `AV:N/AC:L/PR:N/UI:N`. Impact is limited to availability, so `A:L`.

#### Remediation

Add a durable cap for registered clients, stale-client cleanup, or a registration mode that reuses existing clients for identical redirect metadata. Consider operator-configurable quotas by redirect URI pattern and total active client count.

#### Verification

Add tests that registration returns a deterministic OAuth error after the persistent cap is reached, and that cleanup does not delete clients tied to active sessions.

### SEC-003: Direct HTTP exposure has no request read timeout

- **Severity:** Medium
- **CVSS v3.1:** 5.3 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/server.py`

#### Evidence

The server is built on `ThreadingHTTPServer` (`server.py:44-63`). Request bodies are read from `self.rfile.read(length)` after checking `Content-Length` (`server.py:272-289`), but the accepted connection is not assigned a per-request socket timeout in the handler. Body size limits prevent oversized complete requests, but they do not stop a client from opening many connections and slowly sending or withholding the declared body.

#### Preconditions

The Python HTTP server is exposed directly to untrusted clients or the reverse proxy does not enforce upstream/client timeouts and connection limits.

#### Exploit Scenario

An unauthenticated network client opens many `POST /oauth/register`, `POST /oauth/authorize`, or `POST /sse` connections with valid `Content-Length` headers and then trickles data slowly. Each connection can occupy a handler thread. With enough concurrent connections, legitimate OAuth and MCP requests can be delayed or refused.

#### Safe PoC / Validation

Run only against a local development server. Open a small number of connections to `127.0.0.1`, send request headers with a nonzero `Content-Length`, and delay the body. Observe that handler threads remain occupied until the body arrives or the socket closes.

#### Impact

Availability impact for direct or weakly proxied deployments. The recommended reverse-proxy deployment reduces this risk if configured with request, upstream, and connection timeouts.

#### CVSS Rationale

This is unauthenticated and network reachable in direct deployments, but it affects availability only and is mitigated by a correctly configured edge proxy.

#### Remediation

Set a per-connection read timeout in the request handler, expose a bounded timeout configuration, and document required reverse-proxy timeout values. For broader hardening, consider a production HTTP stack with worker and connection limits rather than raw `ThreadingHTTPServer`.

#### Verification

Add endpoint tests that simulate a slow or incomplete body and assert the connection is closed with a deterministic timeout response.

### SEC-004: Sender identity is not bound to SMTP account or configured domain

- **Severity:** Medium
- **CVSS v3.1:** 4.3 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
- **Confidence:** Confirmed, deployment-dependent impact
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/oauth.py`, `src/imap_smtp_mcp/tool_controller.py`, `src/imap_smtp_mcp/send_tools.py`

#### Evidence

`OAuthService.authorize_with_credentials()` requires a syntactically valid `sender_email`, but does not require it to match `smtp_username`, `SMTP_FROM_DOMAIN`, or an SMTP-provider-verified identity (`oauth.py:500-523`). Later, tool dispatch correctly ignores caller-supplied sender overrides and sends with the captured session sender (`tool_controller.py:528-550`). `SendEmailService` places that captured address into the `From` header (`send_tools.py:66-72`).

#### Preconditions

The attacker needs to complete OAuth authorization with IMAP/SMTP credentials and receive `mail:send`. Impact requires an SMTP backend that permits arbitrary or weakly checked `From` addresses.

#### Exploit Scenario

A mailbox user authorizes the connector with valid credentials but enters a misleading sender address. If the SMTP backend accepts the header, later tool calls send mail using that captured identity. The MCP caller cannot override `From` after authorization, which is good, but authorization-time identity is still unverified by this server.

#### Safe PoC / Validation

In a local unit test, call `authorize_with_credentials()` with `smtp_username="alice@example.com"` and `sender_email="ceo@example.org"`, exchange the code, and inspect the decrypted credentials. Current code accepts the mismatch if the sender address is syntactically valid and IMAP verification succeeds.

#### Impact

Bounded outbound email integrity risk, primarily spoofing/social-engineering/compliance impact in deployments where SMTP does not enforce sender ownership.

#### CVSS Rationale

The attacker must be an authorized mail user, and exploitation depends on SMTP policy. Confidentiality and availability are not directly affected.

#### Remediation

Add an explicit sender policy. Conservative options include requiring `sender_email == smtp_username` when the SMTP username is an email address, requiring `sender_email` under `SMTP_FROM_DOMAIN`, or verifying allowed sender identities with the SMTP provider where supported.

#### Verification

Add positive tests for accepted sender identities and negative tests for mismatched sender/domain values. Keep the current tests proving MCP callers cannot override the captured sender.

### SEC-005: Failure audit metadata can log sensitive search terms outside debug mode

- **Severity:** Low
- **CVSS v3.1:** 3.0 `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/imap_smtp_mcp/read_tools.py`, `src/imap_smtp_mcp/tool_controller.py`, `src/imap_smtp_mcp/audit.py`

#### Evidence

`ReadOnlyMailboxService.search_emails()` serializes the full search criteria into `criteria_text` and attaches it to `BackendUnavailableError.metadata` for connection/search failures (`read_tools.py:462-484`). `MailToolController._failure_event()` forwards exception metadata into the audit event (`tool_controller.py:660-672`), and `AuditLogger.log_tool_invocation()` writes metadata even when `MCP_DEBUG_UNREDACTED_LOGS` is false (`audit.py:45-64`). The sanitizer only redacts fields with secret-like key names, so a search value such as a reset code, medical term, or private phrase under `criteria` remains in the audit log.

#### Preconditions

A user performs a search containing sensitive content and the IMAP backend fails during connect/search, or another code path attaches similarly sensitive metadata. A local operator, log shipper, or compromised log reader can access audit logs.

#### Exploit Scenario

A user searches for a private string. During an IMAP outage, the default audit log records the failed operation metadata, including the search criteria JSON. This can place private mailbox context into logs that operators may retain or forward.

#### Safe PoC / Validation

Use the existing failure-path unit pattern with `criteria={"type":"text","value":"private-marker"}` and a failing IMAP adapter, then inspect the audit log. Current code records the serialized criteria in metadata outside debug mode.

#### Impact

Limited confidentiality impact through logs. This does not expose IMAP/SMTP passwords or bearer tokens, but it weakens the expectation that default logs avoid message-content-adjacent data.

#### CVSS Rationale

Local/log access is required, and user action is required to create sensitive search metadata. Confidentiality impact is low and there is no integrity or availability impact.

#### Remediation

Redact or hash search criteria values in default metadata. Preserve coarse fields such as `imap_phase`, `folder`, and `limit`, and only include raw criteria when debug logging is explicitly enabled.

#### Verification

Add a regression test proving failed searches do not write raw search values when `MCP_DEBUG_UNREDACTED_LOGS=false`, and a separate debug-mode test if raw diagnostic criteria are intentionally retained there.

## Exploit Chains

### CHAIN-001: Misconfigured OAuth signing key plus session-scope trust

SEC-001 is the main chain. Known placeholder or dev signing keys make JWT forgery practical for an existing session; the missing session-scope subset check then allows broader scopes and longer expirations than the original authorization grant. Enforcing stored session scopes does not replace strong signing keys, but it materially reduces the blast radius of weak-key deployment and token minting bugs.

### CHAIN-002: Public DCR growth plus threaded server resource exhaustion

SEC-002 and SEC-003 can combine into an availability issue for public deployments without edge controls: repeated registration grows durable state while slow or incomplete HTTP bodies consume handler threads. This remains availability-only; I did not find a path from this chain to credential disclosure or authorization bypass.

## Hardening Recommendations

- Raise the direct dependency floor from `cryptography>=42` to at least a currently patched line, and add a lockfile or hash-pinned build flow. As of this review, PyPI shows `cryptography` `48.0.0` uploaded May 4, 2026, and PyCA advisories identify patched versions `>=46.0.6` for `GHSA-m959-cc7f-wv43` and `>=46.0.7` for `GHSA-p423-j2cm-9vmq`. I did not confirm that these advisories are reachable through the app's Fernet-only usage, so this is dependency hygiene rather than a confirmed app exploit.
- Add runtime JSON Schema validation before tool dispatch. The services validate many fields, but schema-level validation would make missing/extra/wrong-type tool arguments fail consistently as `invalid_input`.
- Add store-level locking or one SQLite connection per request/thread. Prior findings about concurrent access still apply at a hardening level because `OAuthStore` uses one `check_same_thread=False` connection.
- Consider validating JWT header fields (`alg == HS256`, `typ == JWT`) before accepting tokens. The HMAC signature check prevents practical `alg=none` bypass, so this is standards hardening.
- Suppress or customize `BaseHTTPRequestHandler` request-line logging for OAuth authorize URLs. Current `log_message()` writes the raw request line to stderr (`server.py:112-113`), which can include OAuth `state`, `client_id`, and `code_challenge` values.
- Keep edge rate limits for `POST /oauth/token` as documented. Token guessing is not practical due to entropy and PKCE, but unauthenticated token requests can still generate store lookups and audit noise.

## Positive Security Observations

- MCP `tools/list` and `tools/call` require bearer authentication, and tool calls map to explicit read/send/write scopes (`server.py:214-248`, `tool_controller.py:20-41`).
- OAuth redirect registration requires HTTPS, rejects userinfo/fragments/control characters, and uses a configured allowlist (`oauth.py:432-443`, `oauth.py:683-694`).
- Authorization code exchange enforces client ID, redirect URI, PKCE S256, expiration, and one-time use; reuse revokes the credential session (`oauth.py:548-587`).
- Credential sessions are encrypted with Fernet, and refresh tokens are stored as keyed hashes and rotated (`oauth.py:184-199`, `oauth.py:623-655`).
- The authorize form uses a signed, query-bound CSRF cookie plus a hidden form token (`server.py:157-165`, `server.py:736-759`).
- OAuth rate-limit buckets and authorize CSRF tokens are now bounded and sweep expired entries (`server.py:349-381`), addressing the older unbounded-memory class noted in the 2026-05-16 review.
- Production config rejects the default weak signing/cookie secrets and missing encryption key unless the explicit dev escape hatch is set (`config.py:250-251`, `config.py:307-316`).
- IMAP TLS verification cannot be disabled through config; SMTP uses explicit TLS context and timeout keyword arguments (`config.py:329-331`, `imap_adapter.py:62-81`, `smtp_adapter.py:57-73`).
- Write/destructive mailbox operations default to disabled and enforce action flags before adapter/network calls (`config.py:340-355`, `write_tools.py:48-154`).
- Attachment count, decoded size, filename, MIME type, extension, and base64 payloads are bounded/validated for send and retrieval paths (`attachments.py`, `send_tools.py:96-119`, `read_tools.py:573-587`).
- Docker runtime uses a non-root user; compose adds read-only filesystem, `no-new-privileges`, and drops Linux capabilities (`Dockerfile`, `docker-compose.yml:8-27`).

## Assumptions and Limitations

I did not perform live mailbox verification, real SMTP sender-policy testing, reverse-proxy timeout validation, or deployed filesystem permission checks. I did not run a full dependency exploitability audit; dependency observations are based on the direct manifest and public PyPI/PyCA advisory metadata available during the review.

## Appendix

### Command Results

- `git rev-parse HEAD`: `8683d39967c7d12e7946ccc4598e64c67ba91eb2`
- `date -u +"%Y-%m-%dT%H:%M:%SZ"`: `2026-05-20T06:40:09Z`
- `git status --short`: no output before report creation; working tree was clean.
- `pytest -q`: failed, `pytest: command not found`.
- `python3 -m pytest -q`: failed, `No module named pytest`.
- `.venv/bin/python -m pytest -q`: first run under sandbox failed on loopback socket creation with `PermissionError: [Errno 1] Operation not permitted`, after 299 tests passed and 22 endpoint tests failed/errored.
- Escalated `.venv/bin/python -m pytest -q`: `321 passed in 12.86s`.

### External References

- PyPI `cryptography`: https://pypi.org/project/cryptography/
- PyCA/GitHub advisory `GHSA-m959-cc7f-wv43`: https://github.com/pyca/cryptography/security/advisories/GHSA-m959-cc7f-wv43
- PyCA/GitHub advisory `GHSA-p423-j2cm-9vmq`: https://github.com/pyca/cryptography/security/advisories/GHSA-p423-j2cm-9vmq
