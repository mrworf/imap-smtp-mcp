from __future__ import annotations

import pytest

from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import BackendUnavailableError, NotFoundError, PermissionDisabledError
from imap_smtp_mcp.imap_adapter import ImapAdapter
from imap_smtp_mcp.write_tools import WriteMailboxService


class FakeImapClient:
    def __init__(self) -> None:
        self.selected: str | None = None
        self.copied_to: str | None = None
        self.expunge_called = False

    def login(self, user, password):
        return "OK", []

    def select(self, folder):
        self.selected = folder
        return "OK", []

    def uid(self, op, *args):
        if op == "store":
            return "OK", []
        if op == "copy":
            self.copied_to = args[1]
            return "OK", []
        if op == "search":
            return "OK", [b"1 2"]
        return "OK", []

    def expunge(self):
        self.expunge_called = True
        return "OK", []


def _env(monkeypatch):
    entries = {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "465",
        "SMTP_MODE": "ssl",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": "/tmp/imap-smtp-audit",
    }
    for k, v in entries.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def service(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()
    return WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: FakeImapClient()), cfg)


def test_mark_read_state(service):
    service.mark_read_state("u", "p", "Inbox", "42", True)


def test_move_and_copy_and_delete_and_trash(service):
    service.copy_email("u", "p", "Inbox", "Archive", "42")
    service.move_email("u", "p", "Inbox", "Archive", "42")
    service.delete_email_permanent("u", "p", "Inbox", "42")
    service.move_to_trash("u", "p", "Inbox", "42")
    service.empty_trash("u", "p")


def test_action_flags_block(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_EMAIL", "false")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: FakeImapClient()), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: move_email"):
        svc.move_email("u", "p", "Inbox", "Archive", "42")


def test_folder_not_found(service):
    class MissingFolder(FakeImapClient):
        def select(self, folder):
            return "NO", []

    cfg = service._config
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: MissingFolder()), cfg)
    with pytest.raises(NotFoundError, match="Folder not found"):
        svc.copy_email("u", "p", "Inbox", "Archive", "1")


def test_expunge_failure_maps_backend(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class BrokenExpunge(FakeImapClient):
        def expunge(self):
            return "NO", []

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: BrokenExpunge()), cfg)
    with pytest.raises(BackendUnavailableError, match="Failed to expunge deleted email"):
        svc.delete_email_permanent("u", "p", "Inbox", "1")


def test_move_to_trash_does_not_require_move_email_flag(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_EMAIL", "false")
    monkeypatch.setenv("ACTION_MOVE_TO_TRASH", "true")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: FakeImapClient()), cfg)
    svc.move_to_trash("u", "p", "Inbox", "42")


def test_move_to_trash_blocked_by_its_own_flag(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_TO_TRASH", "false")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: FakeImapClient()), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: move_to_trash"):
        svc.move_to_trash("u", "p", "Inbox", "42")
