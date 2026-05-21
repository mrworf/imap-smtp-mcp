# Agent Instructions for `imap-smtp-mcp`

## Scope
These instructions apply to the entire repository.

## Working model
- Implement only the requested scope unless explicitly asked otherwise.
- Prefer minimal, reviewable slices with focused tests and one concise commit per completed slice.
- Prefer small, reviewable commits with passing tests.
- Avoid unrelated refactors and metadata churn.

## Tech defaults
- Use Python 3.12.
- Use `pytest` for tests.
- Keep modules small and dependency-injected for testability.

## Security requirements
- Fail fast on invalid or missing configuration.
- Never log secrets (passwords, tokens, raw auth headers).
- Keep IMAP and SMTP credentials separate in both models and runtime behavior.
- Enforce action flags before any adapter/network calls.

## Project structure conventions
- `src/imap_smtp_mcp/` for implementation.
- `tests/` for unit tests mirroring `src` paths.
- `docs/` for operator docs, security notes, compatibility docs, and user-facing references.

## MCP interface requirements
- Any new API exposed via the MCP interface must define and include an explicit output schema before it is considered complete.

## Testing expectations
- Every new feature requires positive and negative tests.
- Documentation-only changes do not require detailed content assertions. Keep documentation tests limited to policy-level guardrails:
  - documentation must be internally consistent and not contradict itself;
  - documentation must not contain production/real PII, PHI, PCI, or production configuration;
  - redundant, stale, or invalid documentation created by a change must be updated or removed.
- Completed changes require relevant tests passing locally.
- Endpoint tests that bind `127.0.0.1` may fail under sandboxing with `PermissionError`; rerun the same pytest command with loopback permission rather than changing the tests.
- For stdlib IMAP/SMTP clients, pass TLS context/timeout values by keyword (`ssl_context=`, `context=`, `timeout=`); positional arguments can silently map to different parameters across classes.
- Manual mailbox verification depends on external IMAP/SMTP reachability. If SMTP is unreachable, keep adapter timeouts bounded and report the backend error instead of letting MCP requests hang.
- HTTP endpoint tests bind a loopback socket; if sandboxed pytest fails with `PermissionError: Operation not permitted` during server startup, rerun the suite with loopback/network permission rather than weakening the endpoint tests.
- Tests for non-package scripts under `scripts/` must load them by file path or execute them as scripts; do not rely on repository-root importability because CI may run with only `src` on `PYTHONPATH`.

## Definition of done for changes
- Code + tests + docs updated together.
- Deterministic error messages for validation/auth failures.
- No unrelated refactors.
