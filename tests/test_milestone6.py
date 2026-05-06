from __future__ import annotations

import json

from imap_smtp_mcp.audit import AuditEvent, AuditLogger, REDACTED


def test_per_account_and_general_routing(tmp_path):
    logger = AuditLogger(str(tmp_path))
    logger.log_tool_invocation(AuditEvent(request_id="r1", mcp_user="alice", operation="read_email", success=True))
    logger.log_tool_invocation(AuditEvent(request_id="r2", mcp_user=None, operation="startup", success=False, failure_class="config_error"))

    assert (tmp_path / "alice.log").exists()
    assert (tmp_path / "system.log").exists()


def test_required_fields_and_redaction(tmp_path):
    logger = AuditLogger(str(tmp_path))
    logger.log_tool_invocation(AuditEvent(request_id="req-1", mcp_user="bob", operation="send_email", success=False, failure_class="backend_unavailable"))

    payload = json.loads((tmp_path / "bob.log").read_text().strip())
    assert payload["timestamp"]
    assert payload["request_id"] == "req-1"
    assert payload["mcp_user"] == "bob"
    assert payload["operation"] == "send_email"
    assert payload["success"] is False
    assert payload["failure_class"] == "backend_unavailable"
    assert payload["message_content"] == REDACTED


def test_failure_path_logged(tmp_path):
    logger = AuditLogger(str(tmp_path))
    logger.log_tool_invocation(AuditEvent(request_id="req-2", mcp_user="carol", operation="move_email", success=False, failure_class="not_found"))
    lines = (tmp_path / "carol.log").read_text().strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["success"] is False
    assert payload["failure_class"] == "not_found"


def test_rotation(tmp_path):
    logger = AuditLogger(str(tmp_path), rotate_max_bytes=120, rotate_backup_count=2)
    for idx in range(5):
        logger.log_tool_invocation(AuditEvent(request_id=f"r{idx}", mcp_user="alice", operation="op", success=True))

    assert (tmp_path / "alice.log").exists()
    assert (tmp_path / "alice.log.1").exists()
