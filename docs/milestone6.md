# Milestone 6: Audit Logging

## Overview
The audit subsystem records every tool invocation in structured JSON line format and routes records to per-user log files, while non-account/system events are written to `system.log`.

## Log fields
Each event includes:
- `timestamp`
- `request_id`
- `mcp_user`
- `operation`
- `success`
- `failure_class`
- `message_content` (always `[REDACTED]`)

## Redaction policy
Sensitive payloads (including message content and secrets) are never written to logs. The logger always writes a metadata-only event.

## Rotation behavior
The logger supports bounded file size rotation:
- rotate when current log size + incoming event exceeds `rotate_max_bytes`
- keep up to `rotate_backup_count` rotated files (`.1`, `.2`, ...)

Default constructor values are intended for Docker-mounted volumes and can be adjusted by dependency injection.
