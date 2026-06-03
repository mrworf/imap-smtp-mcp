# Deployment guide

This guide deploys Personal Email Connector as a self-hosted IMAP/SMTP MCP server for remote MCP clients.

## Runtime profile
- Python 3.12 container image running `python -m imap_smtp_mcp.server`.
- Non-root runtime user (`mcp`).
- The MCP endpoint is Streamable HTTP-compatible JSON-RPC at `/sse`.
- `/sse` is not a strict legacy long-lived SSE event channel. Native stdio is not implemented; use a separate HTTP-to-stdio bridge if needed.
- `APP_DATA_DIR` must be writable for the SQLite OAuth store, and `AUDIT_LOG_DIR` must be writable for audit logs.

For every supported environment variable, see the [Configuration Reference](configuration.md).

## Client-facing URL
Set `MCP_PUBLIC_BASE_URL` to the public HTTPS URL remote MCP clients will connect to:

```env
MCP_PUBLIC_BASE_URL=https://mail-mcp.example.com
OAUTH_ISSUER=https://mail-mcp.example.com
OAUTH_AUDIENCE=https://mail-mcp.example.com
```

Production public URLs must use HTTPS.

## Recommended reverse proxy deployment
The recommended production shape is TLS termination at nginx/Caddy/Traefik:

```text
ChatGPT -> HTTPS reverse proxy -> http://imap-smtp-mcp:8000
```

Set `MCP_PUBLIC_BASE_URL`, `OAUTH_ISSUER`, and `OAUTH_AUDIENCE` to the external HTTPS origin. The app does not trust or derive OAuth metadata from forwarded proxy headers.

Minimal nginx location:

```nginx
limit_req_zone $binary_remote_addr zone=mcp_oauth:10m rate=30r/m;

location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

For public deployments, also add edge request/IP limits for OAuth endpoints. App-local OAuth caps prevent unbounded in-memory state growth, but they are not a substitute for proxy limits against repeated valid requests such as `GET /oauth/authorize`.

Illustrative nginx OAuth limit:

```nginx
location ~ ^/oauth/(authorize|register|token)$ {
    limit_req zone=mcp_oauth burst=20 nodelay;
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Direct HTTPS deployment
If the app should terminate TLS itself, configure:

```env
MCP_INTERNAL_HTTPS=true
MCP_TLS_CERT_FILE=/run/secrets/mcp.crt
MCP_TLS_KEY_FILE=/run/secrets/mcp.key
```

Self-signed internal HTTPS is intended only for trusted internal deployments:

```env
MCP_ALLOW_SELF_SIGNED_INTERNAL_HTTPS=true
```

This does not relax the requirement that the public client-facing URL uses HTTPS.

## OAuth state
OAuth clients, authorization codes, credential sessions, and hashed refresh tokens are stored in SQLite:

```env
APP_DATA_DIR=/var/lib/imap-smtp-mcp
OAUTH_STORE_PATH=/var/lib/imap-smtp-mcp/oauth.sqlite3
```

Mailbox credentials are encrypted before storage with `OAUTH_ENCRYPTION_KEY`. Refresh tokens are stored as keyed hashes, not plaintext. Keep `APP_DATA_DIR` on persistent storage so ChatGPT clients and sessions survive container restarts.

SQLite is an intentional dependency choice for the single-process, self-hosted runtime profile. The OAuth store serializes in-process SQLite access with a narrow lock, but multi-replica deployments require a shared store/volume and are not otherwise optimized in this pass. If production evidence shows SQLite lock contention, the next step is a small store-level change such as per-operation connections or WAL tuning rather than a broad database abstraction.

## OAuth secrets
Set unique production secrets:

```env
OAUTH_SIGNING_KEY=<long random secret>
OAUTH_COOKIE_SECRET=<long random CSRF cookie signing secret>
OAUTH_DEV_INSECURE_SECRETS=false
OAUTH_ENCRYPTION_KEY=<fernet key>
```

Generate signing and cookie secrets with:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Generate the encryption key with:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

`OAUTH_COOKIE_SECRET` signs the short-lived browser cookie used to protect `/oauth/authorize` credential form submissions from CSRF and authorize-query swapping. Rotating it invalidates only in-flight authorization forms; existing OAuth clients, sessions, and tokens use the SQLite store and signing/encryption keys instead.

## Client integration
For ChatGPT setup, redirect URI allowlists, and notes on untested clients such as Claude, Mistral, and Perplexity, see the [Integration Guide](../INTEGRATIONS.md).

The server supports Dynamic Client Registration and authorization-code + PKCE. Users authorize by entering separate IMAP and SMTP credentials. The IMAP login is verified before tokens are issued.

ChatGPT scans MCP tools during app setup and refresh. `initialize` and `tools/list` are intentionally available without a bearer token so ChatGPT can populate the app's action list. Actual `tools/call` requests remain OAuth-protected, and each mail operation still requires the matching advertised scope before any IMAP or SMTP adapter call.

For ChatGPT App Directory display, configure the public disclosure metadata in both the deployment environment and the ChatGPT app settings:

```env
MCP_APP_WEBSITE_URL=https://mail-mcp.example.com
MCP_APP_PRIVACY_POLICY_URL=https://mail-mcp.example.com/privacy
MCP_APP_TERMS_OF_SERVICE_URL=https://mail-mcp.example.com/terms
```

After changing connector metadata or tool definitions, use ChatGPT's app settings to refresh/rescan tools when available. Published or workspace-managed apps may require recreating or republishing the app before ChatGPT shows updated actions or disclosure links.

The server also rate-limits registration and authorize POST attempts locally, and bounds in-memory OAuth rate-limit and authorize-form CSRF state with `OAUTH_RATE_LIMIT_MAX_BUCKETS` and `OAUTH_AUTHORIZE_CSRF_MAX_TOKENS`. Keep these app-local protections enabled, and use reverse-proxy request/IP limits for public deployments on `GET /oauth/authorize`, `POST /oauth/authorize`, `POST /oauth/register`, and `POST /oauth/token`.

During OAuth authorization, users also confirm the display name and outbound email address that the server will use for sent mail. Set `SMTP_FROM_DOMAIN=example.com` to let the form suggest `smtp_username@example.com` when the SMTP username is only a local part; usernames that already contain `@` are copied as-is. Users may edit the suggested outbound address before authorizing.

After authorization, MCP callers cannot choose `From` or `Reply-To`. `send_email` always uses the captured sender identity, and any caller-supplied sender or reply-to fields are ignored for delivery and recorded in audit metadata with the requested and actual values. The captured outbound sender email must be accepted by the configured SMTP backend; some providers reject or rewrite sender identities that are syntactically valid but not authorized for that SMTP account.

## HTTP and OAuth ownership
The built-in HTTP and OAuth implementation is a deliberate low-dependency design choice for the current compatibility surface. The project owns the small HTTP router, Dynamic Client Registration, authorization-code + PKCE flow, CSRF form protection, token signing, and refresh-token rotation directly. That choice may change if OAuth or MCP interoperability work becomes a major maintenance stream; an ASGI framework or maintained OAuth/JWT library would be the likely direction if the benefits outweigh the current deployment simplicity.

For short troubleshooting windows, set `MCP_DEBUG_UNREDACTED_LOGS=true`. The OAuth authorization page warns users that debug logging is enabled. Audit logs then include sanitized tool arguments/results, email subjects and bodies, and tracebacks for unexpected failures; password, token, key, secret, and authorization fields remain redacted. Keep this disabled in production.

## Docker Compose
Start with:

```bash
mkdir -p runtime/data runtime/audit runtime/ca
docker compose up --build
```

The compose file binds the app to `127.0.0.1:8000` so a local reverse proxy can terminate public TLS.

## Shell debugging
For non-production debugging without Docker, see [Local Shell Debugging](local_debug.md). It covers plain HTTP behind a reverse proxy, binding to a LAN/VPN interface when the proxy runs on another host, and standalone HTTPS with a local self-signed certificate.
