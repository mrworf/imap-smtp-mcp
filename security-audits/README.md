# Security Audits

This folder contains historical security review artifacts for `imap-smtp-mcp`.
The reports are kept together so later reviews can be compared with earlier
findings, methodology, assumptions, and remediation notes.

## Contents

- `security_review_YYYY-MM-DD.md` files are dated Markdown security review
  reports.
- `SECURITY_AUDIT_2026-05-14.md` is an alternate May 14 audit report from the
  same model-comparison effort.
- `Codex55extrahigh.txt` and `opus47high.txt` are prompt/thought-style
  companion records from the May 14 experiment comparing Codex and Opus audit
  behavior.
- `Security Report Comparison.pdf` is the ChatGPT analysis comparing the Opus
  and Codex audit outputs from that experiment.

## Audit Provenance

The May 14 Opus/Codex artifacts were created as an experiment to compare model
behavior, report structure, and finding quality across auditors. The companion
text files preserve the prompt and reasoning-style context for that comparison,
while the PDF records ChatGPT's analysis of the resulting reports.

Later audits without separate prompt/thought files were conducted using Codex
GPT 5.5 at Extra High reasoning. Those reviews followed the security review
workflow directly, rather than preserving full transcript artifacts alongside
the final reports.

## Review Method

The audits generally use a source-first review process focused on security
boundaries in the OAuth flow, MCP interface, IMAP/SMTP adapters, configuration,
deployment defaults, audit logging, and tests.

Reports are written from an external attacker perspective where practical:
public endpoints, OAuth/MCP trust boundaries, operator configuration mistakes,
and realistic exploit chains are prioritized over purely theoretical issues.
Findings usually include practical exploitability analysis, CVSS v3.1 rationale,
safe proof-of-concept notes where appropriate, and explicit assumptions or
limitations.

Follow-up audits compare against earlier findings to distinguish newly observed
issues, fixed issues, and findings that remain open at the time of that specific
review.

## Safety Notes

Proofs of concept in these reports are for local validation and defensive review
only. Do not run them against real mailboxes, third-party systems, production
services, or users.
