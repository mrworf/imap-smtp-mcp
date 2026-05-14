# Manual MCP Compatibility Suite

## Destructive test warning
This suite creates, copies, moves, marks, trashes, permanently deletes, and expunges messages. Run it only against a dedicated test mailbox.

The script requires an interactive TTY and the exact confirmation phrase before it starts.

## What it now tests
The suite starts this MCP server on a temporary local port, performs OAuth Dynamic Client Registration, completes an authorization-code + PKCE flow using the supplied IMAP/SMTP credentials, and calls the real `/sse` MCP endpoint.

The OAuth step follows the same CSRF-protected authorize form path used by browsers: it loads `GET /oauth/authorize`, captures the signed CSRF cookie and hidden form token, submits credentials to `POST /oauth/authorize`, then exchanges the authorization code for a bearer token.

When the suite starts the server from a source checkout, it prepends the repository `src` directory to `PYTHONPATH` for the spawned server process. You do not need to install the package editable before running the suite from this repository.

The suite verifies that the configured inbox, test folder, and trash folder exist before sending mail. During the destructive flow it re-searches for the unique per-run marker before copy and move operations because live IMAP mailbox UID visibility can change between operations.

`/sse` is Streamable HTTP-compatible JSON-RPC for ChatGPT. It is not a strict legacy long-lived SSE stream. Native stdio for Claude Desktop is not implemented; use an external HTTP-to-stdio bridge if needed.

It verifies:

- OAuth authorization with IMAP login verification
- `list_folders`
- `send_email`
- `search_emails`
- `list_emails`
- `read_email`
- `copy_email`
- `move_email`
- `mark_read_state`
- `move_to_trash`
- `delete_email_permanent`
- `empty_trash`

## Required environment
Set real server details and a dedicated test mailbox:

```bash
export IMAP_HOST=imap.example.com
export IMAP_PORT=993
export IMAP_MODE=ssl
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_MODE=starttls

export MCP_COMPAT_TEST_EMAIL=test-mailbox@example.com
export MCP_COMPAT_IMAP_USERNAME=test-mailbox@example.com
export MCP_COMPAT_IMAP_PASSWORD='imap-password'
export MCP_COMPAT_SMTP_USERNAME=test-mailbox@example.com
export MCP_COMPAT_SMTP_PASSWORD='smtp-password'
export MCP_COMPAT_TEST_FOLDER=MCP_COMPAT_TEST
export MCP_COMPAT_TRASH_FOLDER=Trash
```

Optional overrides:

```bash
export MCP_COMPAT_PORT=8123
export MCP_COMPAT_PUBLIC_BASE_URL=http://127.0.0.1:8123
export MCP_COMPAT_SERVER_COMMAND="python -m imap_smtp_mcp.server"
export MCP_COMPAT_INBOX_FOLDER=INBOX
export MCP_COMPAT_HTTP_TIMEOUT_SECONDS=120
export MCP_COMPAT_USE_EXISTING_SERVER=false
```

## Run

```bash
python scripts/manual_mcp_compat_suite.py
```

## Reverse proxy smoke path
For a proxy smoke test, start the server behind nginx/Caddy/Traefik and set:

```bash
export MCP_COMPAT_PUBLIC_BASE_URL=https://mail-mcp.example.com
export MCP_COMPAT_USE_EXISTING_SERVER=true
```

The production ChatGPT-facing URL must remain HTTPS even when the app listens internally on HTTP.
