# Release Checklist

- [x] Verify Personal Email Connector app metadata and documentation use the current product name.
- [x] Run lint checks (`ruff check .`).
- [x] Run type checks (`mypy src`).
- [x] Run full unit test suite (`pytest -q`).
- [x] Verify all action flags default to safe values in deployed environment.
- [x] Verify IMAP/SMTP credentials are supplied separately per MCP user.
- [x] Verify TLS mode/port configuration for IMAP and SMTP is correct.
- [x] Verify audit log path is mounted and writable.
- [x] Confirm secrets are injected through environment (not committed files).
- [x] Confirm rollback image tag is available before deployment.
