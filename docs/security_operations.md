# Security Operations Guide

## Secret management
- Inject all secrets through environment variables or a secret manager.
- Never commit plaintext credentials to repository files.
- Keep IMAP and SMTP credentials distinct for each MCP user account.
- Capture sender display name and outbound email during OAuth, and set `SMTP_FROM_DOMAIN` so the authorize form can suggest the expected sender domain for SMTP usernames without `@`.
- Use a long random `OAUTH_COOKIE_SECRET`; it signs the OAuth authorize CSRF cookie and rotating it invalidates only in-flight authorization forms.

## TLS and certificate handling
- Use `ssl` or `starttls` modes only.
- Keep certificate verification enabled.
- If using custom CAs, mount CA bundle path read-only.

## Action flag hardening
- Sensitive write actions default to `false`; set each `ACTION_*` flag to `true` only when that behavior is required for the deployment.
- Folder lifecycle actions are controlled separately with `ACTION_CREATE_FOLDER`, `ACTION_RENAME_FOLDER`, and `ACTION_DELETE_FOLDER`.
- Enable least-privilege actions per environment.
- Validate effective action flags during startup review.

## Audit logging and retention
- Mount audit log directory to durable storage.
- Use metadata-only logging; avoid message body capture.
- Review `sender_identity_override` events; these record requested versus actual `From`/`Reply-To` values when a caller attempts to spoof sender headers.
- Leave `MCP_DEBUG_UNREDACTED_LOGS=false` outside short troubleshooting windows. When enabled, audit logs include sanitized tool arguments/results, email subjects and bodies, and exception tracebacks; passwords, tokens, keys, secrets, and raw authorization values remain redacted.
- Rotate logs at platform level and define retention policy per compliance needs.

## Incident response basics
- On suspected credential compromise: rotate IMAP/SMTP passwords immediately.
- Disable high-risk action flags while investigating.
- Preserve and export audit logs for timeline reconstruction.
