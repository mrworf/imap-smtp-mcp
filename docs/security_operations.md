# Security Operations Guide

## Secret management
- Inject all secrets through environment variables or a secret manager.
- Never commit plaintext credentials to repository files.
- Keep IMAP and SMTP credentials distinct for each MCP user account.

## TLS and certificate handling
- Use `ssl` or `starttls` modes only.
- Keep certificate verification enabled.
- If using custom CAs, mount CA bundle path read-only.

## Action flag hardening
- Default sensitive write actions to `false` unless required.
- Enable least-privilege actions per environment.
- Validate effective action flags during startup review.

## Audit logging and retention
- Mount audit log directory to durable storage.
- Use metadata-only logging; avoid message body capture.
- Rotate logs at platform level and define retention policy per compliance needs.

## Incident response basics
- On suspected credential compromise: rotate IMAP/SMTP passwords immediately.
- Disable high-risk action flags while investigating.
- Preserve and export audit logs for timeline reconstruction.
