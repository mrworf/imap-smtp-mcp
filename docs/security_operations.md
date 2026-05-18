# Security Operations Guide

## Secret management
- Inject all secrets through environment variables or a secret manager.
- Never commit plaintext credentials to repository files.
- Keep IMAP and SMTP credentials distinct for each MCP user account.
- Capture sender display name and outbound email during OAuth, and set `SMTP_FROM_DOMAIN` so the authorize form can suggest the expected sender domain for SMTP usernames without `@`.
- Use long random `OAUTH_SIGNING_KEY` and `OAUTH_COOKIE_SECRET` values. `OAUTH_COOKIE_SECRET` signs the OAuth authorize CSRF cookie and rotating it invalidates only in-flight authorization forms.
- Leave `OAUTH_DEV_INSECURE_SECRETS=false` outside local testing.

## TLS and certificate handling
- Use `ssl` or `starttls` modes only.
- Keep certificate verification enabled.
- If using custom CAs, mount CA bundle path read-only.

## OAuth abuse controls
- Configure `OAUTH_ALLOWED_REDIRECT_URI_PATTERNS` narrowly for the clients you expect, such as the ChatGPT connector redirect.
- Review failed `oauth_register` audit events to see the attempted `redirect_uris` when tuning the allowlist.
- Keep the local registration and authorize rate limits enabled even when a reverse proxy also rate-limits traffic.
- Keep `OAUTH_RATE_LIMIT_MAX_BUCKETS` and `OAUTH_AUTHORIZE_CSRF_MAX_TOKENS` bounded so hostile OAuth traffic cannot grow in-memory state without limit. These app-local caps protect the process; public deployments should still enforce request and IP limits at the reverse proxy.
- Treat a refresh-token reuse error as a session compromise; the server revokes the credential session when reuse is detected.

## Action flag hardening
- Sensitive write actions default to `false`; set each `ACTION_*` flag to `true` only when that behavior is required for the deployment.
- Folder lifecycle actions are controlled separately with `ACTION_CREATE_FOLDER`, `ACTION_RENAME_FOLDER`, and `ACTION_DELETE_FOLDER`.
- Enable least-privilege actions per environment.
- Validate effective action flags during startup review.

## Audit logging and retention
- Mount audit log directory to durable storage.
- Per-user audit filenames are derived from a hash of the MCP subject; the original subject remains inside each JSON audit line as `mcp_user`.
- Use metadata-only logging; avoid message body capture.
- Review `sender_identity_override` events; these record requested versus actual `From`/`Reply-To` values when a caller attempts to spoof sender headers.
- Leave `MCP_DEBUG_UNREDACTED_LOGS=false` outside short troubleshooting windows. When enabled, audit logs include sanitized tool arguments/results, email subjects and bodies, and exception tracebacks; passwords, tokens, keys, secrets, and raw authorization values remain redacted.
- Rotate logs at platform level and define retention policy per compliance needs.

## Incident response basics
- On suspected credential compromise: rotate IMAP/SMTP passwords immediately.
- Disable high-risk action flags while investigating.
- Preserve and export audit logs for timeline reconstruction.
