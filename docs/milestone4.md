# Milestone 4 implementation notes

- `send_email` uses SMTP credentials only and sends through `SmtpAdapter`.
- Sender identity comes from the OAuth credential session and is validated before network calls; MCP callers cannot choose `From` or `Reply-To`.
- Recipient addresses are validated before any SMTP/IMAP network calls.
- Save-to-sent behavior is enabled by default and can be disabled per call using `append_to_sent=False`.
- If SMTP send succeeds but append-to-sent fails, the service raises a deterministic error: `Email sent but failed to append to sent folder`.
- Attachments are intentionally out of scope for this milestone slice.
