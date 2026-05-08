# Deployment guide (Milestone 7)

## Runtime profile
- Python 3.12 container image with a multi-stage build.
- Non-root runtime user (`mcp`).
- Read-only root filesystem compatibility.
- Writable mount required for `AUDIT_LOG_DIR`.

## Required environment
Copy `env.example` and replace all placeholder secrets before deploying:

```bash
cp env.example .env
```

Then set per-user IMAP/SMTP credentials and server host/port/mode values.

## Docker Compose
Start with:

```bash
mkdir -p runtime/audit runtime/ca
docker compose up --build
```

Notes:
- `read_only: true` enforces immutable container root filesystem.
- `/tmp` is mounted as `tmpfs` for runtime temporary files.
- `/var/lib/imap-smtp-mcp/audit` must remain writable to persist audit logs.
- If `IMAP_TLS_CA_BUNDLE_PATH` is set, mount the corresponding CA file into `/run/secrets`.

## Startup failure modes
Startup fails fast in these scenarios:
- Missing required environment variables (for example `MCP_ALLOWED_USERS`, endpoint settings, or credentials).
- Invalid type/format for typed values (`IMAP_PORT`, `SMTP_PORT`, booleans, etc.).
- Missing writable audit log mount when `AUDIT_LOG_DIR` cannot be created/written.


## CI image publishing
- The unified CI workflow publishes `ghcr.io/<repository_owner>/imap-smtp-mcp` only for `push` events to `main`.
- Image build/push is skipped unless docker-relevant files changed (`Dockerfile`, `docker-compose.yml`, `pyproject.toml`, `src/**`, `.github/workflows/ci.yml`).
- Tags include `main`, `sha-<commit>`, and `latest` on the default branch.
