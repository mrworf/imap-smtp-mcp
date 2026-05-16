from __future__ import annotations

import pytest

from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from imap_smtp_mcp.imap_adapter import ImapAdapter, encode_mailbox_name
from imap_smtp_mcp.write_tools import WriteMailboxService


class FakeImapClient:
    def __init__(self) -> None:
        self.selected: str | None = None
        self.copied_to: str | None = None
        self.expunge_called = False
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.created_folder: str | None = None
        self.renamed_folder: tuple[str, str] | None = None
        self.deleted_folder: str | None = None

    def login(self, user, password):
        return "OK", []

    def select(self, folder):
        self.selected = folder
        return "OK", []

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "Inbox"',
            b'(\\HasNoChildren) "/" "Archive"',
            b'(\\HasNoChildren) "/" "Trash"',
            b'(\\HasNoChildren) "/" "MCP Smoke marker"',
            b'(\\HasNoChildren) "/" "MCP Smoke Renamed marker"',
            b'(\\HasNoChildren) "/" "Quote \\" Folder"',
            b'(\\HasNoChildren) "/" "Slash \\\\ Folder"',
        ]

    def create(self, folder):
        self.created_folder = folder
        return "OK", []

    def rename(self, source, target):
        self.renamed_folder = (source, target)
        return "OK", []

    def delete(self, folder):
        self.deleted_folder = folder
        return "OK", []

    def uid(self, op, *args):
        self.calls.append((op, args))
        if op == "fetch":
            return "OK", [(b"42 (UID 42)",)]
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
        "OAUTH_DEV_INSECURE_SECRETS": "true",
        "ACTION_MARK_READ_STATE": "true",
        "ACTION_MOVE_EMAIL": "true",
        "ACTION_COPY_EMAIL": "true",
        "ACTION_DELETE_EMAIL_PERMANENT": "true",
        "ACTION_MOVE_TO_TRASH": "true",
        "ACTION_EMPTY_TRASH": "true",
        "ACTION_CREATE_FOLDER": "true",
        "ACTION_RENAME_FOLDER": "true",
        "ACTION_DELETE_FOLDER": "true",
    }
    for k, v in entries.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def service(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()
    return WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()), cfg)


def test_mark_read_state(service):
    service.mark_read_state("u", "p", "Inbox", "42", True)


def test_move_and_copy_and_delete_and_trash(service):
    service.copy_email("u", "p", "Inbox", "Archive", "42")
    service.move_email("u", "p", "Inbox", "Archive", "42")
    service.delete_email_permanent("u", "p", "Inbox", "42")
    service.move_to_trash("u", "p", "Inbox", "42")
    service.empty_trash("u", "p")


@pytest.mark.parametrize("uid", ["1:*", "1,2", "1:5", "*", "0", "-1", "+1", " "])
@pytest.mark.parametrize("operation", ["mark_read_state", "copy_email", "move_email", "move_to_trash", "delete_email_permanent"])
def test_single_message_write_tools_reject_sequence_set_uids(monkeypatch, uid, operation):
    _env(monkeypatch)
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    with pytest.raises(InvalidInputError, match="uid must"):
        if operation == "mark_read_state":
            svc.mark_read_state("u", "p", "Inbox", uid, True)
        elif operation == "copy_email":
            svc.copy_email("u", "p", "Inbox", "Archive", uid)
        elif operation == "move_email":
            svc.move_email("u", "p", "Inbox", "Archive", uid)
        elif operation == "move_to_trash":
            svc.move_to_trash("u", "p", "Inbox", uid)
        else:
            svc.delete_email_permanent("u", "p", "Inbox", uid)

    assert client.calls == []


def test_folder_lifecycle_operations_success(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    svc.create_folder("u", "p", "MCP_TEST")
    svc.rename_folder("u", "p", "Archive", "MCP_TEST_RENAMED")
    svc.delete_folder("u", "p", "Archive")

    assert client.created_folder == encode_mailbox_name("MCP_TEST")
    assert client.renamed_folder == (encode_mailbox_name("Archive"), encode_mailbox_name("MCP_TEST_RENAMED"))
    assert client.deleted_folder == encode_mailbox_name("Archive")


def test_folder_lifecycle_quotes_names_with_spaces_and_special_characters(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    svc.create_folder("u", "p", "MCP Smoke marker")
    svc.rename_folder("u", "p", "MCP Smoke marker", "MCP Smoke Renamed fresh")
    svc.delete_folder("u", "p", 'Quote " Folder')
    svc.create_folder("u", "p", "Slash \\ Folder")

    assert client.created_folder == encode_mailbox_name("Slash \\ Folder")
    assert client.renamed_folder == (encode_mailbox_name("MCP Smoke marker"), encode_mailbox_name("MCP Smoke Renamed fresh"))
    assert client.deleted_folder == encode_mailbox_name('Quote " Folder')


def test_copy_and_move_quote_target_folder_names_with_spaces(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    svc.copy_email("u", "p", "Inbox", "MCP Smoke Renamed marker", "42")
    assert client.copied_to == encode_mailbox_name("MCP Smoke Renamed marker")

    svc.move_email("u", "p", "Inbox", "MCP Smoke Renamed marker", "42")
    assert client.copied_to == encode_mailbox_name("MCP Smoke Renamed marker")


def test_folder_operations_validate_names(service):
    with pytest.raises(InvalidInputError, match="folder must not be empty"):
        service.create_folder("u", "p", " ")
    with pytest.raises(InvalidInputError, match="source_folder must be single-line"):
        service.rename_folder("u", "p", "Bad\nFolder", "Target")
    with pytest.raises(InvalidInputError, match="folder must be single-line"):
        service.delete_folder("u", "p", "Bad\nFolder")


def test_folder_operations_action_flags_before_adapter(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_CREATE_FOLDER", "false")
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    with pytest.raises(PermissionDisabledError, match="Action disabled: create_folder"):
        svc.create_folder("u", "p", "MCP_TEST")
    assert client.created_folder is None
    assert client.calls == []


def test_rename_folder_source_missing_and_target_exists(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class MissingSource(FakeImapClient):
        def list(self):
            return "OK", [b'(\\HasNoChildren) "/" "Archive"']

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: MissingSource()), cfg)
    with pytest.raises(NotFoundError, match="Folder not found: Missing"):
        svc.rename_folder("u", "p", "Missing", "Target")

    class ExistingTarget(FakeImapClient):
        def list(self):
            return "OK", [b'(\\HasNoChildren) "/" "Archive"', b'(\\HasNoChildren) "/" "Target"']

    svc2 = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: ExistingTarget()), cfg)
    with pytest.raises(InvalidInputError, match="Folder already exists: Target"):
        svc2.rename_folder("u", "p", "Archive", "Target")


def test_folder_operation_backend_failures(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class FailingFolders(FakeImapClient):
        def create(self, folder):
            return "NO", []

        def rename(self, source, target):
            return "NO", []

        def delete(self, folder):
            return "NO", []

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: FailingFolders()), cfg)

    with pytest.raises(BackendUnavailableError, match="Failed to create folder"):
        svc.create_folder("u", "p", "MCP_TEST")
    with pytest.raises(BackendUnavailableError, match="Failed to rename folder"):
        svc.rename_folder("u", "p", "Archive", "MCP_TEST")
    with pytest.raises(BackendUnavailableError, match="Failed to delete folder"):
        svc.delete_folder("u", "p", "Archive")


def test_action_flags_block(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_EMAIL", "false")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: move_email"):
        svc.move_email("u", "p", "Inbox", "Archive", "42")


def test_folder_not_found(service):
    class MissingFolder(FakeImapClient):
        def select(self, folder):
            return "NO", []

    cfg = service._config
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: MissingFolder()), cfg)
    with pytest.raises(NotFoundError, match="Folder not found"):
        svc.copy_email("u", "p", "Inbox", "Archive", "1")


def test_write_tools_missing_source_uid_is_not_found(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class MissingUid(FakeImapClient):
        def uid(self, op, *args):
            if op == "fetch":
                return "OK", [None]
            return super().uid(op, *args)

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: MissingUid()), cfg)

    with pytest.raises(NotFoundError, match="Email not found: 42"):
        svc.copy_email("u", "p", "Inbox", "Archive", "42")
    with pytest.raises(NotFoundError, match="Email not found: 42"):
        svc.move_email("u", "p", "Inbox", "Archive", "42")
    with pytest.raises(NotFoundError, match="Email not found: 42"):
        svc.mark_read_state("u", "p", "Inbox", "42", True)
    with pytest.raises(NotFoundError, match="Email not found: 42"):
        svc.delete_email_permanent("u", "p", "Inbox", "42")
    with pytest.raises(NotFoundError, match="Email not found: 42"):
        svc.move_to_trash("u", "p", "Inbox", "42")


def test_copy_move_missing_target_folder_is_not_found(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class MissingTarget(FakeImapClient):
        def list(self):
            return "OK", [b'(\\HasNoChildren) "/" "Inbox"', b'(\\HasNoChildren) "/" "Trash"']

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: MissingTarget()), cfg)

    with pytest.raises(NotFoundError, match="Folder not found: Archive"):
        svc.copy_email("u", "p", "Inbox", "Archive", "42")
    with pytest.raises(NotFoundError, match="Folder not found: Archive"):
        svc.move_email("u", "p", "Inbox", "Archive", "42")


def test_copy_failure_after_preflight_maps_backend_unavailable(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class CopyFails(FakeImapClient):
        def uid(self, op, *args):
            if op == "copy":
                return "NO", [b"copy failed"]
            return super().uid(op, *args)

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: CopyFails()), cfg)

    with pytest.raises(BackendUnavailableError, match="Failed to copy email"):
        svc.copy_email("u", "p", "Inbox", "Archive", "42")


def test_copy_preflight_runs_after_action_flag(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_COPY_EMAIL", "false")
    cfg = load_config()
    client = FakeImapClient()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: client), cfg)

    with pytest.raises(PermissionDisabledError, match="Action disabled: copy_email"):
        svc.copy_email("u", "p", "Inbox", "Archive", "42")
    assert client.calls == []


def test_expunge_failure_maps_backend(monkeypatch):
    _env(monkeypatch)
    cfg = load_config()

    class BrokenExpunge(FakeImapClient):
        def expunge(self):
            return "NO", []

    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: BrokenExpunge()), cfg)
    with pytest.raises(BackendUnavailableError, match="Failed to expunge deleted email"):
        svc.delete_email_permanent("u", "p", "Inbox", "1")


def test_move_to_trash_does_not_require_move_email_flag(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_EMAIL", "false")
    monkeypatch.setenv("ACTION_MOVE_TO_TRASH", "true")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()), cfg)
    svc.move_to_trash("u", "p", "Inbox", "42")


def test_move_to_trash_blocked_by_its_own_flag(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ACTION_MOVE_TO_TRASH", "false")
    cfg = load_config()
    svc = WriteMailboxService(ImapAdapter(cfg, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: move_to_trash"):
        svc.move_to_trash("u", "p", "Inbox", "42")
