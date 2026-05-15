# Example Prompts

These prompts are written for ChatGPT when this IMAP/SMTP MCP connector is enabled. They favor clear mailbox names, bounded result sizes, and explicit safety rules for write operations.

## Common Read Prompts

- List my mail folders.
- Show the 20 most recent messages in `INBOX`.
- Show emails from today in `INBOX` using an IMAP date range like `SINCE 13-May-2026 BEFORE 14-May-2026`, then summarize the senders and subjects.
- Search `INBOX` for messages containing `invoice` and return up to 25 matches.
- Read the message with UID `<uid>` from `INBOX`, limiting the body to 4000 characters.
- Show the sender identity this connector will use for outgoing mail.

## Common Send And Organize Prompts

- Send an email to `person@example.com` with subject `Hello from MCP` and the body `This is a test message from my IMAP/SMTP MCP connector.`
- Create a folder named `MCP Test <unique-marker>`, then rename it to `MCP Test Renamed <unique-marker>`.
- Send a test email to myself with subject `MCP owned message <unique-marker>`, search for that exact marker, and only copy, move, mark read or unread, trash, or permanently delete messages that match that marker.
- Move the MCP-created message with UID `<uid>` from `INBOX` to `MCP Test Renamed <unique-marker>`, then copy it back to `INBOX`.
- Mark only the MCP-created message with UID `<uid>` as read, then unread.
- Move only the MCP-created message with UID `<uid>` to Trash. Permanently delete only that same MCP-created message if it is still identifiable by the unique marker.
- Delete the folder `MCP Test Renamed <unique-marker>` only after confirming it was created during this prompt and contains no user mail.

## Full Capability Smoke Prompt

Use this prompt when you want ChatGPT to exercise all current MCP capabilities without intentionally modifying existing mailbox content:

```text
Run a safe IMAP/SMTP MCP smoke test against my mailbox.

Use a unique marker like MCP-SMOKE-<timestamp>-<random>. First get_sender_identity so you know the display name and outbound sender email, then list_folders and confirm the configured INBOX and Trash folder names. Create a folder named MCP Smoke <marker>, then rename_folder it to MCP Smoke Renamed <marker>.

Send an email to my own outbound sender email with subject MCP Smoke <marker> and a short body containing the marker. Use search_emails in INBOX for the exact marker until the sent test message is visible, then list_emails in INBOX and read_email for only that matching UID.

Only operate on messages whose subject or body contains the marker. For the matching MCP-created message, copy_email it to MCP Smoke Renamed <marker>, mark_read_state it read and then unread, move_email the copied or matching MCP-created message back if needed, and move_to_trash only an MCP-created matching UID. If a matching MCP-created message is in Trash, delete_email_permanent only that matching UID.

For empty_trash, use a guarded skip: list or search Trash first, and call empty_trash only if Trash is confirmed to contain no messages except MCP-created messages with this marker. If Trash contains anything else or cannot be confirmed safe, skip empty_trash and report the reason.

Finally delete_folder MCP Smoke Renamed <marker> only after confirming it was created in this test and contains no non-test mail. Report each tool used and any skipped destructive step.
```

Capabilities exercised or intentionally guarded by this prompt: `list_folders`, `search_emails`, `list_emails`, `read_email`, `get_sender_identity`, `send_email`, `mark_read_state`, `move_email`, `copy_email`, `delete_email_permanent`, `move_to_trash`, `empty_trash`, `create_folder`, `rename_folder`, and `delete_folder`.
