from __future__ import annotations

import json

import pytest

from imap_smtp_mcp.audit import AuditLogger
from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import AuthSessionError, PermissionDisabledError
from imap_smtp_mcp.oauth import MailCredentials
from imap_smtp_mcp.tool_controller import TOOL_SCHEMAS, TOOL_SCOPES, MailToolController, WRITE_SCOPE, _annotations_for


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
        }
    ]
    log_lines = (tmp_path / "subject.log").read_text(encoding="utf-8").splitlines()
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
