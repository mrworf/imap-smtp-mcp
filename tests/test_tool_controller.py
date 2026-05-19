from __future__ import annotations

import json

import pytest

from imap_smtp_mcp.audit import AuditLogger, _audit_filename
from imap_smtp_mcp.attachments import AttachmentData
from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import AuthSessionError, BackendUnavailableError, InvalidInputError, PermissionDisabledError
from imap_smtp_mcp.oauth import MailCredentials
from imap_smtp_mcp.tool_controller import READ_SCOPE, SEND_SCOPE, TOOL_SCHEMAS, TOOL_SCOPES, MailToolController, WRITE_SCOPE, _annotations_for


@pytest.fixture
def controller_env(monkeypatch, tmp_path):
    env = {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "465",
        "SMTP_MODE": "ssl",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": str(tmp_path),
        "OAUTH_DEV_INSECURE_SECRETS": "true",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)


class FakeWriteService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def create_folder(self, username: str, password: str, folder: str) -> None:
        self.calls.append(("create_folder", (username, password, folder)))

    def rename_folder(self, username: str, password: str, source_folder: str, target_folder: str) -> None:
        self.calls.append(("rename_folder", (username, password, source_folder, target_folder)))

    def delete_folder(self, username: str, password: str, folder: str) -> None:
        self.calls.append(("delete_folder", (username, password, folder)))


class FakeReadService:
    def list_folders(self, username: str, password: str) -> tuple[str, ...]:
        return ("INBOX", "Sent")

    def list_emails(self, username: str, password: str, folder: str, offset: int = 0, limit: int = 20):
        return ({"uid": "1", "subject": "Hello"},)

    def get_email_attachment(self, username: str, password: str, folder: str, uid: str, attachment_id: str):
        return {
            "filename": "note.txt",
            "content_type": "text/plain",
            "size_bytes": 5,
            "content_base64": "aGVsbG8=",
        }


class FailingReadService:
    def search_emails(self, username: str, password: str, folder: str, criteria: object, limit: int = 50):
        raise BackendUnavailableError("IMAP search failed", metadata={"imap_phase": "search", "folder": folder, "criteria": json.dumps(criteria, sort_keys=True, separators=(",", ":")), "limit": str(limit)}) from RuntimeError("socket timeout")


def _credentials() -> MailCredentials:
    return MailCredentials(
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
        sender_display_name="Test Sender",
        sender_email="sender@example.com",
    )


def _legacy_credentials() -> MailCredentials:
    return MailCredentials(
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
    )


class FakeSendService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def send_email(
        self,
        smtp_username: str,
        smtp_password: str,
        imap_username: str,
        imap_password: str,
        from_address: str,
        to_addresses: tuple[str, ...],
        subject: str,
        body_text: str,
        from_display_name: str | None = None,
        reply_to_address: str | None = None,
        append_to_sent: bool = True,
        attachments: tuple[AttachmentData, ...] = (),
    ) -> None:
        self.calls.append(
            {
                "smtp_username": smtp_username,
                "smtp_password": smtp_password,
                "imap_username": imap_username,
                "imap_password": imap_password,
                "from_address": from_address,
                "to_addresses": to_addresses,
                "subject": subject,
                "body_text": body_text,
                "from_display_name": from_display_name,
                "reply_to_address": reply_to_address,
                "append_to_sent": append_to_sent,
                "attachments": attachments,
            }
        )


def test_folder_tool_schemas_scopes_and_annotations() -> None:
    assert TOOL_SCOPES["create_folder"] == (WRITE_SCOPE,)
    assert TOOL_SCOPES["rename_folder"] == (WRITE_SCOPE,)
    assert TOOL_SCOPES["delete_folder"] == (WRITE_SCOPE,)
    assert TOOL_SCHEMAS["create_folder"]["required"] == ["folder"]
    assert TOOL_SCHEMAS["rename_folder"]["required"] == ["source_folder", "target_folder"]
    assert TOOL_SCHEMAS["delete_folder"]["required"] == ["folder"]
    assert _annotations_for("create_folder")["readOnlyHint"] is False
    assert _annotations_for("rename_folder")["destructiveHint"] is False
    assert _annotations_for("delete_folder")["destructiveHint"] is True


def test_send_tool_schema_does_not_accept_sender_identity_from_caller() -> None:
    schema = TOOL_SCHEMAS["send_email"]
    assert schema["required"] == ["to_addresses", "subject", "body_text"]
    assert "from_address" not in schema["properties"]
    assert "from_display_name" not in schema["properties"]
    assert "reply_to" not in schema["properties"]
    assert "attachments" in schema["properties"]


def test_sender_identity_tool_schema_scope_and_annotations() -> None:
    assert TOOL_SCOPES["get_sender_identity"] == (SEND_SCOPE,)
    assert TOOL_SCHEMAS["get_sender_identity"] == {"type": "object", "properties": {}, "additionalProperties": False}
    assert _annotations_for("get_sender_identity") == {"readOnlyHint": True, "destructiveHint": False}


def test_attachment_read_tool_schema_scope_and_annotations(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    tools = controller.list_tools()
    attachment_tool = next(tool for tool in tools if tool["name"] == "get_email_attachment")

    assert TOOL_SCOPES["get_email_attachment"] == (READ_SCOPE,)
    assert TOOL_SCHEMAS["get_email_attachment"]["required"] == ["folder", "uid", "attachment_id"]
    assert _annotations_for("get_email_attachment") == {"readOnlyHint": True, "destructiveHint": False}
    assert attachment_tool["outputSchema"]["required"] == ["filename", "content_type", "size_bytes", "content_base64"]
    assert "base64" in attachment_tool["description"]
    assert "1048576 bytes" in attachment_tool["description"]
    assert "text/html" in attachment_tool["description"]


def test_send_tool_schema_documents_attachment_limits(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    send_tool = next(tool for tool in controller.list_tools() if tool["name"] == "send_email")

    assert "Personal IMAP/SMTP Mail Connector" in send_tool["description"]
    assert "10 attachments" in send_tool["description"]
    assert "1048576 decoded bytes" in send_tool["description"]
    assert "base64" in send_tool["inputSchema"]["properties"]["attachments"]["description"]
    assert send_tool["inputSchema"]["properties"]["attachments"]["maxItems"] == 10


def test_tool_descriptions_include_sender_identity_without_backend_usernames(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))

    read_tool = next(tool for tool in controller.list_tools(_credentials()) if tool["name"] == "read_email")

    assert "Personal IMAP/SMTP Mail Connector" in read_tool["description"]
    assert "Test Sender <sender@example.com>" in read_tool["description"]
    assert "imap-user" not in read_tool["description"]
    assert "smtp-user" not in read_tool["description"]


def test_tool_descriptions_without_sender_identity_do_not_render_none(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))

    read_tool = next(tool for tool in controller.list_tools(_legacy_credentials()) if tool["name"] == "read_email")

    assert "Personal IMAP/SMTP Mail Connector" in read_tool["description"]
    assert "None" not in read_tool["description"]
    assert "imap-user" not in read_tool["description"]
    assert "smtp-user" not in read_tool["description"]


def test_read_tools_return_object_shaped_structured_content(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    controller.read_service = FakeReadService()

    assert controller.call_tool("list_folders", {}, _credentials(), request_id="folders-1", subject="subject") == {"folders": ["INBOX", "Sent"]}
    assert controller.call_tool(
        "list_emails",
        {"folder": "INBOX", "offset": 0, "limit": 10},
        _credentials(),
        request_id="emails-1",
        subject="subject",
    ) == {"emails": [{"uid": "1", "subject": "Hello"}]}
    assert controller.call_tool(
        "get_email_attachment",
        {"folder": "INBOX", "uid": "1", "attachment_id": "part-2"},
        _credentials(),
        request_id="attachment-1",
        subject="subject",
    ) == {"filename": "note.txt", "content_type": "text/plain", "size_bytes": 5, "content_base64": "aGVsbG8="}


def test_folder_tool_dispatch_uses_session_credentials(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_write = FakeWriteService()
    controller.write_service = fake_write

    assert controller.call_tool("create_folder", {"folder": "New"}, _credentials(), request_id="1", subject="subject") == {"created": True}
    assert controller.call_tool(
        "rename_folder",
        {"source_folder": "New", "target_folder": "Renamed"},
        _credentials(),
        request_id="2",
        subject="subject",
    ) == {"renamed": True}
    assert controller.call_tool("delete_folder", {"folder": "Renamed"}, _credentials(), request_id="3", subject="subject") == {"deleted": True}

    assert fake_write.calls == [
        ("create_folder", ("imap-user", "imap-pass", "New")),
        ("rename_folder", ("imap-user", "imap-pass", "New", "Renamed")),
        ("delete_folder", ("imap-user", "imap-pass", "Renamed")),
    ]


def test_sender_identity_tool_returns_captured_identity(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))

    result = controller.call_tool("get_sender_identity", {}, _credentials(), request_id="identity-1", subject="subject")

    assert result == {"sender_display_name": "Test Sender", "sender_email": "sender@example.com"}


def test_sender_identity_tool_requires_current_sender_identity(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    with pytest.raises(AuthSessionError, match="reauthorize to view sender identity"):
        controller.call_tool("get_sender_identity", {}, _legacy_credentials(), request_id="identity-2", subject="subject")

    assert fake_send.calls == []


def test_send_tool_uses_session_sender_and_audits_spoof_attempt(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    result = controller.call_tool(
        "send_email",
        {
            "from_address": "spoof@example.net",
            "from_display_name": "Spoof",
            "reply_to": "reply@example.net",
            "to_addresses": ["bob@example.com"],
            "subject": "Subject",
            "body_text": "Body",
        },
        _credentials(),
        request_id="send-1",
        subject="subject",
    )

    assert result == {"sent": True}
    assert fake_send.calls == [
        {
            "smtp_username": "smtp-user",
            "smtp_password": "smtp-pass",
            "imap_username": "imap-user",
            "imap_password": "imap-pass",
            "from_address": "sender@example.com",
            "to_addresses": ("bob@example.com",),
            "subject": "Subject",
            "body_text": "Body",
            "from_display_name": "Test Sender",
            "reply_to_address": "sender@example.com",
            "append_to_sent": True,
            "attachments": (),
        }
    ]
    log_lines = (tmp_path / _audit_filename("subject")).read_text(encoding="utf-8").splitlines()
    override = next(json.loads(line) for line in log_lines if json.loads(line)["operation"] == "sender_identity_override")
    assert override["request_id"] == "send-1"
    assert override["metadata"]["requested_from_address"] == "spoof@example.net"
    assert override["metadata"]["requested_from_display_name"] == "Spoof"
    assert override["metadata"]["requested_reply_to"] == "reply@example.net"
    assert override["metadata"]["actual_sender_email"] == "sender@example.com"
    assert override["metadata"]["actual_sender_display_name"] == "Test Sender"
    assert "Body" not in "\n".join(log_lines)


def test_send_tool_requires_sender_identity_before_network(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    with pytest.raises(AuthSessionError, match="reauthorize before sending email"):
        controller.call_tool(
            "send_email",
            {"to_addresses": ["bob@example.com"], "subject": "Subject", "body_text": "Body"},
            _legacy_credentials(),
            request_id="send-2",
            subject="subject",
        )
    assert fake_send.calls == []


def test_send_tool_action_flag_blocks_before_sender_identity(controller_env, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ACTION_SEND_EMAIL", "false")
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    with pytest.raises(PermissionDisabledError, match="Action disabled: send_email"):
        controller.call_tool(
            "send_email",
            {"to_addresses": ["bob@example.com"], "subject": "Subject", "body_text": "Body"},
            _legacy_credentials(),
            request_id="send-3",
            subject="subject",
        )
    assert fake_send.calls == []


def test_send_tool_passes_validated_attachments(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    result = controller.call_tool(
        "send_email",
        {
            "to_addresses": ["bob@example.com"],
            "subject": "Subject",
            "body_text": "Body",
            "attachments": [{"filename": "note.txt", "content_type": "Text/Plain", "content_base64": "aGVsbG8="}],
        },
        _credentials(),
        request_id="send-attachments",
        subject="subject",
    )

    assert result == {"sent": True}
    attachments = fake_send.calls[0]["attachments"]
    assert attachments == (AttachmentData(filename="note.txt", content_type="text/plain", content=b"hello"),)


def test_send_tool_rejects_attachment_before_send_service(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    fake_send = FakeSendService()
    controller.send_service = fake_send

    with pytest.raises(InvalidInputError, match="blocked by extension"):
        controller.call_tool(
            "send_email",
            {
                "to_addresses": ["bob@example.com"],
                "subject": "Subject",
                "body_text": "Body",
                "attachments": [{"filename": "script.js", "content_type": "text/plain", "content_base64": "aGVsbG8="}],
            },
            _credentials(),
            request_id="send-attachments-blocked",
            subject="subject",
        )

    assert fake_send.calls == []


def test_tool_failure_audit_includes_exception_details(controller_env, tmp_path) -> None:
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path)))
    controller.read_service = FailingReadService()

    with pytest.raises(BackendUnavailableError, match="IMAP search failed"):
        controller.call_tool(
            "search_emails",
            {"folder": "INBOX", "criteria": {"type": "text", "value": "hello"}, "limit": 5},
            _credentials(),
            request_id="search-1",
            subject="subject",
        )

    payload = json.loads((tmp_path / _audit_filename("subject")).read_text(encoding="utf-8").splitlines()[0])
    assert payload["failure_class"] == "backend_unavailable"
    assert payload["metadata"]["imap_phase"] == "search"
    assert payload["metadata"]["folder"] == "INBOX"
    assert payload["exception_type"] == "BackendUnavailableError"
    assert payload["exception_message"] == "IMAP search failed"
    assert "RuntimeError: socket timeout" in payload["exception_cause"]
    assert "arguments" not in payload
    assert "exception_traceback" not in payload


def test_debug_tool_audit_logs_sanitized_arguments_results_and_traceback(controller_env, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_DEBUG_UNREDACTED_LOGS", "true")
    config = load_config()
    controller = MailToolController(config, audit_logger=AuditLogger(str(tmp_path), debug_unredacted_logs=True))
    controller.send_service = FakeSendService()

    result = controller.call_tool(
        "send_email",
        {
            "to_addresses": ["bob@example.com"],
            "subject": "Subject",
            "body_text": "Debug body",
            "smtp_password": "bad-secret",
            "attachments": [{"filename": "note.txt", "content_type": "text/plain", "content_base64": "c2VjcmV0"}],
        },
        _credentials(),
        request_id="send-debug",
        subject="subject",
    )

    assert result == {"sent": True}
    payload = json.loads((tmp_path / _audit_filename("subject")).read_text(encoding="utf-8").splitlines()[-1])
    encoded = json.dumps(payload)
    assert payload["arguments"]["body_text"] == "Debug body"
    assert payload["arguments"]["smtp_password"] == "[REDACTED]"
    assert payload["arguments"]["attachments"][0]["content_base64"] == "[REDACTED]"
    assert payload["result"] == {"sent": True}
    assert "bad-secret" not in encoded
