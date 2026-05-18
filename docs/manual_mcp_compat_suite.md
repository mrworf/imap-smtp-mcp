# Manual MCP Compatibility Suite

## Destructive test warning
This suite creates, copies, moves, marks, trashes, permanently deletes, and expunges messages. Run it only against a dedicated test mailbox.

The script requires an interactive TTY and the exact confirmation phrase before it starts.

## What it now tests
The suite starts this MCP server on a temporary local port, performs OAuth Dynamic Client Registration, completes an authorization-code + PKCE flow using the supplied IMAP/SMTP credentials, and calls the real `/sse` MCP endpoint.

The OAuth step follows the same CSRF-protected authorize form path used by browsers: it loads `GET /oauth/authorize`, captures the signed CSRF cookie and hidden form token, submits credentials to `POST /oauth/authorize`, then exchanges the authorization code for a bearer token.

When the suite starts the server from a source checkout, it prepends the repository `src` directory to `PYTHONPATH` for the spawned server process. You do not need to install the package editable before running the suite from this repository.
It also configures `OAUTH_ALLOWED_REDIRECT_URI_PATTERNS` for the suite's ChatGPT-compatible redirect URI.

The suite verifies that the configured inbox and trash folder exist before sending mail. It sends one MCP-generated message with an allowed text attachment, retrieves that attachment with `get_email_attachment`, verifies that blocked outbound attachments fail without delivery, injects one direct SMTP fixture message with blocked HTML/JavaScript attachments, confirms MCP reports but refuses to retrieve those blocked attachments, creates a unique temporary test folder, renames it once, uses it for copy/move/mark/trash operations, and deletes it before finishing. During the destructive flow it re-searches for the unique per-run marker before copy and move operations because live IMAP mailbox UID visibility can change between operations.

Read/list tool responses are object-shaped for ChatGPT compatibility; for example, `list_folders` returns a `folders` array and `list_emails` returns an `emails` array.

`/sse` is Streamable HTTP-compatible JSON-RPC for ChatGPT. It is not a strict legacy long-lived SSE stream. Native stdio for Claude Desktop is not implemented; use an external HTTP-to-stdio bridge if needed.

It verifies:

- OAuth authorization with IMAP login verification
- `list_folders`
- `send_email`
- `search_emails`
- `list_emails`
- `read_email`
- `get_email_attachment` when a matching message exposes an allowed attachment
- `create_folder`
- `rename_folder`
- `copy_email`
- `move_email`
- `mark_read_state`
- `move_to_trash`
- `delete_email_permanent`
- `empty_trash`
- `delete_folder`

## Required environment
Set real server details and a dedicated test mailbox:

```bash
export IMAP_HOST=imap.example.com
export IMAP_PORT=993
export IMAP_MODE=ssl
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_MODE=starttls
export SMTP_FROM_DOMAIN=example.com

export MCP_COMPAT_TEST_EMAIL=test-mailbox@example.com
export MCP_COMPAT_SENDER_DISPLAY_NAME='MCP Compatibility Test'
export MCP_COMPAT_SENDER_EMAIL=test-mailbox@example.com
export MCP_COMPAT_IMAP_USERNAME=test-mailbox@example.com
export MCP_COMPAT_IMAP_PASSWORD='imap-password'
export MCP_COMPAT_SMTP_USERNAME=test-mailbox@example.com
export MCP_COMPAT_SMTP_PASSWORD='smtp-password'
export MCP_COMPAT_TRASH_FOLDER=Trash
```

The suite uses `SMTP_HOST`, `SMTP_PORT`, and `SMTP_MODE` twice: once through the MCP server for normal `send_email`, and once directly from the suite to create a blocked inbound attachment fixture that the MCP server must refuse to retrieve.

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

The suite submits the OAuth sender display name and outbound email during authorization. The `send_email` call itself does not include `from_address`; the server must use the captured sender identity and reject spoofing attempts from MCP callers.
