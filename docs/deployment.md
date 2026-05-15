# Deployment guide

## Runtime profile
- Python 3.12 container image running `python -m imap_smtp_mcp.server`.
- Non-root runtime user (`mcp`).
- The MCP endpoint is Streamable HTTP-compatible JSON-RPC at `/sse`.
- `/sse` is not a strict legacy long-lived SSE event channel. Native stdio for Claude Desktop is not implemented; use a separate HTTP-to-stdio bridge if needed.
- `APP_DATA_DIR` must be writable for the SQLite OAuth store, and `AUDIT_LOG_DIR` must be writable for audit logs.

For every supported environment variable, see the [Configuration Reference](configuration.md).

## ChatGPT-facing URL
Set `MCP_PUBLIC_BASE_URL` to the public HTTPS URL ChatGPT will connect to:

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

Forward these headers:

```text
Host
X-Forwarded-Proto
X-Forwarded-Host
X-Forwarded-For
```

Enable proxy trust only for known proxy networks:

```env
MCP_TRUST_PROXY_HEADERS=true
MCP_ALLOWED_PROXY_CIDRS=127.0.0.1/32,172.16.0.0/12
```

Minimal nginx location:

```nginx
location / {
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

This does not relax the requirement that the public ChatGPT-facing URL uses HTTPS.

## OAuth state
OAuth clients, authorization codes, credential sessions, and hashed refresh tokens are stored in SQLite:

```env
APP_DATA_DIR=/var/lib/imap-smtp-mcp
OAUTH_STORE_PATH=/var/lib/imap-smtp-mcp/oauth.sqlite3
```

Mailbox credentials are encrypted before storage with `OAUTH_ENCRYPTION_KEY`. Refresh tokens are stored as keyed hashes, not plaintext. Keep `APP_DATA_DIR` on persistent storage so ChatGPT clients and sessions survive container restarts.

Multi-replica deployments require a shared store/volume and are not otherwise optimized in this pass.

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

## ChatGPT setup
Use this public MCP URL in ChatGPT Apps & Connectors:

```text
https://mail-mcp.example.com/sse
```

ChatGPT discovers OAuth from:

```text
https://mail-mcp.example.com/.well-known/oauth-protected-resource
https://mail-mcp.example.com/.well-known/oauth-authorization-server
```

The server supports Dynamic Client Registration and authorization-code + PKCE. Users authorize by entering separate IMAP and SMTP credentials. The IMAP login is verified before tokens are issued.

Restrict Dynamic Client Registration to known redirect destinations. For ChatGPT, allow its connector OAuth redirect:

```env
OAUTH_ALLOWED_REDIRECT_URI_PATTERNS=https://chatgpt\.com/connector/oauth/cb
```

During OAuth authorization, users also confirm the display name and outbound email address that the server will use for sent mail. Set `SMTP_FROM_DOMAIN=example.com` to let the form suggest `smtp_username@example.com` when the SMTP username is only a local part; usernames that already contain `@` are copied as-is. Users may edit the suggested outbound address before authorizing.

After authorization, MCP callers cannot choose `From` or `Reply-To`. `send_email` always uses the captured sender identity, and any caller-supplied sender or reply-to fields are ignored for delivery and recorded in audit metadata with the requested and actual values.

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
