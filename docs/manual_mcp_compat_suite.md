# Manual MCP Compatibility Suite (Real Inbox)

## ⚠️ Destructive test warning
This suite is intentionally destructive. It creates, copies, moves, marks, trashes, permanently deletes, and expunges messages.

- Never run this against a production mailbox.
- Use a dedicated test mailbox/account that can send to itself.
- The script requires an interactive TTY and exact confirmation text before running.

## Purpose
Validate compatibility of your MCP-facing IMAP/SMTP deployment against real servers by exercising every exposed mail API from a CLI flow similar to LLM tool calls.

## Script location
- `scripts/manual_mcp_compat_suite.py`

## Required setup
1. Dedicated mailbox email address for tests.
2. Dedicated test folder (e.g. `MCP_COMPAT_TEST`).
3. Known trash folder path.
4. A command that accepts JSON-RPC on stdin and performs MCP `tools/call` against your endpoint.

## Example run
```bash
python scripts/manual_mcp_compat_suite.py \
  --mcp-command "your-mcp-cli --endpoint http://localhost:3000" \
  --test-email test-mailbox@example.com \
  --inbox-folder INBOX \
  --test-folder MCP_COMPAT_TEST \
  --trash-folder Trash
```

## What it verifies
- `list_folders`
- `send_email` (self-send)
- `search_emails` (polling)
- `list_emails`
- `read_email` (checks marker content and sender)
- `copy_email`
- `move_email`
- `mark_read_state` true/false
- `move_to_trash`
- `delete_email_permanent`
- `empty_trash`

## Notes
- This suite is manual-only and not intended for CI automation.
- If your MCP transport emits extra logs, ensure one JSON response object is still emitted to stdout per call.
