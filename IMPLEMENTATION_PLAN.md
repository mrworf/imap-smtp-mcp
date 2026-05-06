# IMAP/SMTP MCP Server Implementation Plan

## Goal
Build a Docker-hosted MCP server for ChatGPT that supports secure, audited IMAP/SMTP operations with separate protocol credentials, granular feature flags, and full unit-test coverage (including negative/blocked-path tests).

## Guiding principles
- Security-first defaults (least privilege, secure transport, strict authn/authz, no sensitive data leakage in logs).
- MCP ergonomics aligned with ChatGPT best practices where not detrimental to security.
- Milestones are minimal viable slices that can be implemented and validated independently.
- Every externally visible capability gets positive and negative unit tests.

---

## Milestone 0 — Architecture & contract baseline (MVP planning slice)
**Objective:** Freeze interfaces before implementation.

### Scope
1. Define MCP tool contract (inputs/outputs/errors) for:
   - `list_folders`
   - `search_emails`
   - `list_emails`
   - `read_email`
   - `mark_read_state`
   - `move_email`
   - `copy_email`
   - `delete_email_permanent`
   - `move_to_trash`
   - `empty_trash`
   - `send_email`
2. Define configuration schema (env vars) for:
   - Allowed MCP users (server-auth users)
   - Global IMAP endpoint + protocol mode + port
   - Global SMTP endpoint + protocol mode + port
   - Sent-folder path, trash-folder path
   - Per-action on/off flags
   - Audit log directory
3. Define per-user secret model allowing separate IMAP and SMTP creds.
4. Define threat model and logging redaction policy.

### Deliverables
- `docs/mcp_tool_contract.md`
- `docs/configuration_schema.md`
- `docs/security_threat_model.md`

### Exit criteria
- Team can implement without changing contract.
- Unknown/unsupported options have deterministic error behavior documented.

---

## Milestone 1 — Project scaffold + config loader + secure authentication ✅ (Completed)
**Objective:** Stand up runnable MCP service shell with robust auth/config loading.

### Scope
1. Create MCP server app skeleton with dependency boundaries:
   - transport/session layer
   - authn/authz middleware
   - imap adapter
   - smtp adapter
   - audit logger
2. Implement env-based config loader with strict validation:
   - Required vars fail fast on startup.
   - Invalid ports/protocols/action flags fail fast.
3. Implement MCP user authentication against allowed user list from env.
4. Implement per-user account mapping with distinct IMAP and SMTP credentials.
5. Implement action capability matrix from env flags.

### Deliverables
- Startup-ready server binary/container entrypoint.
- Config parser with typed model and validation errors.
- Auth middleware enforcing allowed MCP users.

### Unit tests
- Valid config loads.
- Missing/invalid env values fail startup.
- Unauthorized MCP user rejected.
- Authorized user accepted.
- IMAP-only/SMTP-only creds cannot be swapped accidentally.
- Disabled action capability is rejected before mailbox/network call.

### Exit criteria
- Service starts with valid env and rejects invalid env/auth deterministically.

---

## Milestone 2 — IMAP connectivity layer (SSL/TLS/non-standard ports) ✅ (Completed)
**Objective:** Build hardened IMAP client abstraction supporting configured transport variants.

### Scope
1. IMAP adapter supporting:
   - SSL (implicit TLS) mode
   - STARTTLS mode
   - custom port
2. Secure TLS settings:
   - cert verification on by default
   - hostname validation on
   - optional pinned CA bundle path (if configured)
3. Connection lifecycle and retry policy (safe bounded retries).
4. Folder operations:
   - list folders
   - resolve configured sent/trash folders

### Deliverables
- Reusable IMAP client abstraction with mocked interface for tests.

### Unit tests
- SSL mode path used when configured.
- STARTTLS upgrade path used when configured.
- Non-standard port respected.
- TLS verification failures surface secure errors.
- Folder listing success and failure cases.

### Exit criteria
- IMAP adapter validated with deterministic behavior in mocked tests.

---

## Milestone 3 — Read-only mailbox features ✅ (Completed)
**Objective:** Deliver all read capabilities through MCP tools.

### Scope
1. Implement `list_folders`.
2. Implement `search_emails` with query sanitization and bounded result size.
3. Implement `list_emails` in any folder with pagination.
4. Implement `read_email` returning structured metadata/body with safe truncation options.
5. Standardized error taxonomy (not found, permission disabled, backend unavailable, invalid input).

### Deliverables
- Production-ready read tool handlers.

### Unit tests
- Positive flows for each read tool.
- Invalid folder/query/input rejected.
- Access blocked when corresponding action flags disable read operations.
- Backend timeout/error mapped to stable MCP error.

### Exit criteria
- ChatGPT can browse/search/read mail safely with bounded responses.

---

## Milestone 4 — SMTP connectivity + send workflow ✅ (Completed)
**Objective:** Implement secure send-mail path with configurable sender identity.

### Scope
1. SMTP adapter supporting:
   - SSL (implicit TLS)
   - STARTTLS
   - custom port
2. Use SMTP-specific credentials (separate from IMAP).
3. `send_email` tool:
   - from-address and display name configurable in MCP config
   - recipient validation
   - subject/body/optional MIME attachments (if included in contract)
4. Optional save-to-sent workflow (default ON):
   - after successful send, append RFC822 copy to configured IMAP sent folder.

### Deliverables
- End-to-end send handler with optional append-to-sent.

### Unit tests
- SMTP SSL and STARTTLS branches.
- Non-standard port respected.
- Sending disabled via action flag is blocked.
- Append-to-sent default true; can be disabled.
- Append failure handling policy tested (e.g., send success + append failure reported clearly).
- Invalid sender/recipient/address format rejected.

### Exit criteria
- Reliable secure sending with optional sent-folder archival.

---

## Milestone 5 — Write mailbox actions with feature-flag enforcement ✅ (Completed)
**Objective:** Implement all state-changing IMAP actions with centralized policy checks.

### Scope
1. Implement:
   - `mark_read_state` (read/unread)
   - `move_email`
   - `copy_email`
   - `delete_email_permanent`
   - `move_to_trash`
   - `empty_trash`
2. Central preflight authorization check per action flag.
3. Idempotency and safety checks (where possible).
4. Explicit trash-folder handling from global config.

### Deliverables
- Full write-operation toolset with consistent policy gate.

### Unit tests
- Positive flow for every write action.
- Each action blocked when its flag is OFF.
- Nonexistent message/folder errors handled.
- Expunge/permanent delete safeguards honored.
- Cross-folder move/copy edge cases.

### Exit criteria
- All mutation tools functional and policy-governed.

---

## Milestone 6 — Audit logging (per-account + general)
**Objective:** Provide complete, secure, traceable activity logs.

### Scope
1. Implement structured audit logger with:
   - one file per MCP user/account
   - one general server log for non-account/system events
2. Log every tool invocation outcome:
   - timestamp, request id/correlation id
   - authenticated MCP user
   - target operation
   - success/failure + failure class
3. Sensitive data redaction:
   - never log plaintext passwords/tokens
   - redact message content by default (metadata-only)
4. Log rotation strategy compatible with Docker filesystem volumes.

### Deliverables
- Audit logging subsystem and log format docs.

### Unit tests
- Correct file routing (per-account vs general).
- Required fields exist in each log event.
- Redaction tests ensure secrets are never written.
- Failure paths still logged.

### Exit criteria
- Full auditable trail with secure redaction guarantees.

---

## Milestone 7 — Containerization, hardening, and deployment profile
**Objective:** Deliver production-grade Docker packaging and runtime posture.

### Scope
1. Dockerfile (multi-stage, minimal runtime image).
2. Non-root runtime user.
3. Read-only root filesystem compatibility (except mounted log/config paths).
4. Health/readiness endpoints if MCP runtime supports them.
5. Example `.env` and `docker-compose.yml` with all flags and protocol/port options.

### Deliverables
- `Dockerfile`
- `docker-compose.yml`
- `docs/deployment.md`
- `env.example`

### Unit tests
- Config parsing from representative container env sets.
- Startup behavior in missing-volume/missing-env scenarios.

### Exit criteria
- Container runs securely with documented volume/env requirements.

---

## Milestone 8 — Comprehensive test completion & quality gates
**Objective:** Ensure complete automated coverage including negative/security tests.

### Scope
1. Achieve unit tests for all tools, adapters, auth, policy, and logging.
2. Add negative tests for:
   - unauthorized user attempts
   - disabled action attempts
   - invalid protocol/port combos
   - mailbox access failures
   - TLS downgrade or verification failure paths
3. Add contract tests for stable MCP responses/error shapes.
4. Add CI workflow enforcing tests + lint + type checks.

### Deliverables
- Final test suite and CI pipeline.

### Exit criteria
- Every requested functionality and blocked-path behavior covered by automated tests.

---

## Milestone 9 — Security review + release readiness
**Objective:** Final validation before rollout.

### Scope
1. Perform secure code review against threat model.
2. Validate default action flags are safe-by-default.
3. Verify docs for operational security (secret injection, cert management, log retention).
4. Produce release checklist and rollback guidance.

### Deliverables
- `docs/release_checklist.md`
- `docs/security_operations.md`

### Exit criteria
- Team can deploy with clear operational and security guidance.

---

## Suggested implementation order for parallel agents
1. Milestone 0 (single owner)
2. Milestones 1 + 2 in parallel after contract freeze
3. Milestones 3 + 4 in parallel (read vs send paths)
4. Milestone 5 (depends on 2)
5. Milestone 6 (starts early, finalize after tools)
6. Milestone 7 (after 1 stable)
7. Milestones 8 + 9 at integration stage

## Definition of done (overall)
- All required features implemented behind explicit action flags.
- Separate IMAP/SMTP credentials supported per MCP-authenticated user.
- SSL/TLS and non-standard ports supported for both protocols.
- Configurable sender identity and sent-folder archival behavior (default on).
- Complete audit trail split per-account + general logs.
- Comprehensive unit tests, including negative tests that fail on policy bypass.
