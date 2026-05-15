# Configuration Reference

This reference describes the environment variables used by the IMAP/SMTP MCP server. Start from `env.example`, then replace example values with production secrets and mailbox settings.

## Server, Public URL, Proxy, TLS, And Debug

- `MCP_HOST`: bind host for the HTTP server. Default: `0.0.0.0`.
- `MCP_PORT`: bind port for the HTTP server. Default: `8000`.
- `MCP_PUBLIC_BASE_URL`: public base URL ChatGPT uses to reach this server. Production URLs must use HTTPS.
- `MCP_ALLOW_INSECURE_PUBLIC_URL`: development-only escape hatch for non-HTTPS public URLs outside localhost. Default: `false`.
- `MCP_TRUST_PROXY_HEADERS`: trust forwarded host/proto/client headers from known proxies. Default: `false`.
- `MCP_ALLOWED_PROXY_CIDRS`: comma-separated CIDR allowlist for trusted reverse proxies. Default: `127.0.0.1/32,::1/128`.
- `MCP_INTERNAL_HTTPS`: make the app terminate TLS directly instead of plain HTTP behind a proxy. Default: `false`.
- `MCP_ALLOW_SELF_SIGNED_INTERNAL_HTTPS`: allow self-signed certificates for direct internal HTTPS. Default: `false`; requires `MCP_INTERNAL_HTTPS=true`.
- `MCP_TLS_CERT_FILE`: certificate path for direct internal HTTPS.
- `MCP_TLS_KEY_FILE`: private key path for direct internal HTTPS.
- `MCP_DEBUG_UNREDACTED_LOGS`: include sanitized tool arguments/results, message content, and tracebacks in audit logs for short debugging windows. Default: `false`; do not enable for production mailboxes.

## OAuth And Storage

- `APP_DATA_DIR`: persistent data directory for local state. Default: `/var/lib/imap-smtp-mcp`.
- `OAUTH_STORE_PATH`: SQLite path for OAuth clients, codes, sessions, and refresh-token hashes. Default: `$APP_DATA_DIR/oauth.sqlite3`.
- `OAUTH_ISSUER`: OAuth issuer URL. Default: `MCP_PUBLIC_BASE_URL`.
- `OAUTH_AUDIENCE`: bearer-token audience. Default: `MCP_PUBLIC_BASE_URL`.
- `OAUTH_SIGNING_KEY`: secret used to sign bearer tokens. Required for production HTTPS deployments.
- `OAUTH_COOKIE_SECRET`: secret used to sign short-lived OAuth authorization-form CSRF cookies. Required for production HTTPS deployments.
- `OAUTH_ENCRYPTION_KEY`: Fernet key used to encrypt mailbox credentials in the OAuth store. Required for production HTTPS deployments.
- `OAUTH_REQUIRED_SCOPES`: space- or comma-separated required scopes. Default: `mail:read mail:send mail:write`.
- `OAUTH_ALLOWED_REDIRECT_URI_PATTERNS`: comma- or newline-separated regular expressions for allowed Dynamic Client Registration redirect URIs. Required for DCR; for ChatGPT use `https://chatgpt\.com/connector/oauth/cb`.
- `OAUTH_ACCESS_TOKEN_TTL_SECONDS`: access-token lifetime. Default: `3600`.
- `OAUTH_AUTH_CODE_TTL_SECONDS`: authorization-code lifetime. Default: `300`.
- `OAUTH_REFRESH_TOKEN_TTL_SECONDS`: refresh-token lifetime. Default: `2592000`.
- `OAUTH_USERNAME_CLAIM`: token claim used as the MCP user subject. Default: `sub`.

## IMAP

- `IMAP_HOST`: IMAP server host. Required.
- `IMAP_PORT`: IMAP server port. Required.
- `IMAP_MODE`: IMAP transport mode, either `ssl` or `starttls`. Required.
- `IMAP_SENT_FOLDER`: folder used when appending sent mail. Required.
- `IMAP_TRASH_FOLDER`: folder used by trash operations. Required.
- `IMAP_TLS_VERIFY`: require certificate verification. Default: `true`; setting `false` is rejected.
- `IMAP_TLS_CA_BUNDLE_PATH`: optional custom CA bundle path for IMAP TLS validation.
- `IMAP_MAX_RETRIES`: number of IMAP connection retries after the first attempt. Default: `2`.

## SMTP And Sender Suggestion

- `SMTP_HOST`: SMTP server host. Required.
- `SMTP_PORT`: SMTP server port. Required.
- `SMTP_MODE`: SMTP transport mode, either `ssl` or `starttls`. Required.
- `SMTP_FROM_DOMAIN`: optional bare domain used by the OAuth form to suggest an outbound sender email from an SMTP username local part.
- `SMTP_TIMEOUT_SECONDS`: SMTP network timeout. Default: `30`.

## Action Flags

Action flags enable or disable tool families before any adapter/network call. They default to enabled in code, but `env.example` disables the more destructive operations.

- `ACTION_LIST_FOLDERS`: allow folder listing.
- `ACTION_SEARCH_EMAILS`: allow email search.
- `ACTION_LIST_EMAILS`: allow recent email listing.
- `ACTION_READ_EMAIL`: allow reading email bodies.
- `ACTION_SEND_EMAIL`: allow sending email.
- `ACTION_MARK_READ_STATE`: allow marking messages read or unread.
- `ACTION_MOVE_EMAIL`: allow moving messages between folders.
- `ACTION_COPY_EMAIL`: allow copying messages between folders.
- `ACTION_DELETE_EMAIL_PERMANENT`: allow permanent message deletion.
- `ACTION_MOVE_TO_TRASH`: allow moving messages to the configured trash folder.
- `ACTION_EMPTY_TRASH`: allow emptying the configured trash folder.
- `ACTION_CREATE_FOLDER`: allow creating folders.
- `ACTION_RENAME_FOLDER`: allow renaming folders.
- `ACTION_DELETE_FOLDER`: allow deleting folders.

## Audit Logs

- `AUDIT_LOG_DIR`: directory for structured audit log files. Required and must be writable.

Audit logs redact secrets by default. When `MCP_DEBUG_UNREDACTED_LOGS=true`, passwords, tokens, keys, secrets, and raw authorization headers remain redacted.

## Manual Compatibility Suite

These variables are used by `scripts/manual_mcp_compat_suite.py`, not by the production server. The suite is destructive and should be run only against a dedicated test mailbox.

- `MCP_COMPAT_TEST_EMAIL`: mailbox address used as the test recipient.
- `MCP_COMPAT_SENDER_DISPLAY_NAME`: sender display name submitted during OAuth. Default: `MCP Compatibility Test`.
- `MCP_COMPAT_SENDER_EMAIL`: outbound sender email submitted during OAuth. Default: `MCP_COMPAT_TEST_EMAIL`.
- `MCP_COMPAT_IMAP_USERNAME`: IMAP username for the test mailbox.
- `MCP_COMPAT_IMAP_PASSWORD`: IMAP password for the test mailbox.
- `MCP_COMPAT_SMTP_USERNAME`: SMTP username for the test mailbox.
- `MCP_COMPAT_SMTP_PASSWORD`: SMTP password for the test mailbox.
- `MCP_COMPAT_TRASH_FOLDER`: trash folder expected by the suite.
- `MCP_COMPAT_INBOX_FOLDER`: inbox folder expected by the suite. Default: `INBOX`.
- `MCP_COMPAT_PORT`: temporary server port. Default: `8123`.
- `MCP_COMPAT_HOST`: temporary server bind host. Default: `127.0.0.1`.
- `MCP_COMPAT_PUBLIC_BASE_URL`: public base URL used by the suite. Default: `http://127.0.0.1:$MCP_COMPAT_PORT`.
- `MCP_COMPAT_SERVER_COMMAND`: server command for the launched process. Default: current Python running `-m imap_smtp_mcp.server`.
- `MCP_COMPAT_HTTP_TIMEOUT_SECONDS`: HTTP timeout for suite requests. Default: `120`.
- `MCP_COMPAT_USE_EXISTING_SERVER`: use an already running server instead of launching one. Default: `false`.
