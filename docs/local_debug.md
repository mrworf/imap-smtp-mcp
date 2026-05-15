# Local Shell Debugging

This workflow is for debugging only. It creates local runtime directories, uses debug-only OAuth secrets when you do not provide real ones, and can generate a short-lived self-signed certificate for standalone HTTPS testing.

Docker remains the recommended deployment shape. For production, use persistent secrets, persistent storage, and a public HTTPS reverse proxy.

## Required Mail Endpoint Env

The helper reads IMAP/SMTP endpoint settings from your shell:

```bash
export IMAP_HOST=imap.example.com
export IMAP_PORT=993
export IMAP_MODE=ssl
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_MODE=starttls
export SMTP_FROM_DOMAIN=example.com
export IMAP_SENT_FOLDER=Sent
export IMAP_TRASH_FOLDER=Trash
export MCP_DEBUG_UNREDACTED_LOGS=false
```

OAuth users still enter their own IMAP and SMTP usernames/passwords in the authorization form. The form also captures the sender display name and outbound email address; `SMTP_FROM_DOMAIN` only powers the email suggestion.

Temporarily set `MCP_DEBUG_UNREDACTED_LOGS=true` when debugging connector failures. The OAuth form will warn users, and audit logs will include sanitized tool arguments/results, message bodies, and exception tracebacks while still redacting password, token, key, secret, and authorization fields.

## Reverse Proxy Destination

Run plain HTTP when TLS is terminated by nginx, Caddy, Traefik, or another reverse proxy:

```bash
.venv/bin/python scripts/run_debug_server.py \
  --mode reverse-proxy \
  --host 127.0.0.1 \
  --port 8000 \
  --public-base-url https://mail-mcp.example.com
```

If the reverse proxy runs somewhere else on your LAN or VPN, bind to an interface it can reach:

```bash
.venv/bin/python scripts/run_debug_server.py \
  --mode reverse-proxy \
  --host 0.0.0.0 \
  --port 8000 \
  --public-base-url https://mail-mcp.example.com
```

You can also use a specific LAN IP instead of `0.0.0.0`. When binding to a non-loopback host, restrict access with a firewall; this is still a debug server.

## Standalone HTTPS

Run direct HTTPS when you want the app to terminate TLS itself during local testing:

```bash
.venv/bin/python scripts/run_debug_server.py \
  --mode https \
  --host 127.0.0.1 \
  --port 8443 \
  --public-base-url https://localhost:8443
```

If `.tmp/debug/tls/debug-mcp.crt` and `.tmp/debug/tls/debug-mcp.key` do not exist, the helper uses `openssl` to generate a seven-day self-signed certificate. To provide your own files:

```bash
.venv/bin/python scripts/run_debug_server.py \
  --mode https \
  --host 0.0.0.0 \
  --port 8443 \
  --public-base-url https://mail-mcp-debug.example.com:8443 \
  --cert-file ./local.crt \
  --key-file ./local.key
```

Generated certificates and generated OAuth secrets are debug-only. Do not reuse them for production.
The helper also seeds `OAUTH_ALLOWED_REDIRECT_URI_PATTERNS` for ChatGPT connector redirects so Dynamic Client Registration works during local testing.

## Inspect Resolved Env

Use `--print-env` to see the non-secret configuration without starting the long-running server:

```bash
.venv/bin/python scripts/run_debug_server.py \
  --mode reverse-proxy \
  --host 0.0.0.0 \
  --port 8000 \
  --public-base-url https://mail-mcp.example.com \
  --print-env
```

The helper creates:

```text
.tmp/debug/data
.tmp/debug/audit
.tmp/debug/tls
```

It sets `APP_DATA_DIR`, `AUDIT_LOG_DIR`, and `OAUTH_STORE_PATH` to those local paths.

## Readiness Check

Check the selected host and port:

```bash
curl -fsS http://127.0.0.1:8000/readyz
```

For standalone HTTPS with the generated certificate:

```bash
curl -k -fsS https://127.0.0.1:8443/readyz
```

## Manual Compatibility Suite

You can point the manual suite at the running debug server by using a public base URL that matches the helper:

```bash
export MCP_PUBLIC_BASE_URL=https://mail-mcp.example.com
export MCP_SERVER_URL=https://mail-mcp.example.com/sse
.venv/bin/python scripts/manual_mcp_compat_suite.py --use-running-server
```

For local HTTP-only debugging, keep the listener private and use the helper’s debug-only insecure public URL behavior only outside production.
