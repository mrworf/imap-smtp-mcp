from __future__ import annotations

import pytest

from imap_smtp_mcp.audit import AuditLogger
from imap_smtp_mcp.config import load_config
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


def _credentials() -> MailCredentials:
    return MailCredentials(
        imap_username="imap-user",
        imap_password="imap-pass",
        smtp_username="smtp-user",
        smtp_password="smtp-pass",
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
