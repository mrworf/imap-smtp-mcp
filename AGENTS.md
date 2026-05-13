# Agent Instructions for `imap-smtp-mcp`

## Scope
These instructions apply to the entire repository.

## Working model
- Follow `IMPLEMENTATION_PLAN.md` milestone boundaries strictly.
- Implement only the requested milestone unless explicitly asked otherwise.
- Prefer small, reviewable commits with passing tests.

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
- `docs/` for milestone docs and contracts.

## Testing expectations
- Every new feature requires positive and negative tests.
- Milestone completion requires relevant tests passing locally.
- HTTP endpoint tests bind a loopback socket; if sandboxed pytest fails with `PermissionError: Operation not permitted` during server startup, rerun the suite with loopback/network permission rather than weakening the endpoint tests.
- Tests for non-package scripts under `scripts/` must load them by file path or execute them as scripts; do not rely on repository-root importability because CI may run with only `src` on `PYTHONPATH`.

## Definition of done for changes
- Code + tests + docs updated together.
- Deterministic error messages for validation/auth failures.
- No unrelated refactors.
