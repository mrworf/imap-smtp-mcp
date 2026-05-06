import ssl

import pytest

from imap_smtp_mcp.config import ConfigError, load_config
from imap_smtp_mcp.imap_adapter import FolderResolutionError, ImapAdapter, ImapConnectionError, ImapTlsError


class FakeImapClient:
    def __init__(self, folders=None):
        self._folders = folders or [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Sent"', b'(\\HasNoChildren) "/" "Trash"']
        self.started_tls = False
        self.logged_in = False

    def login(self, user: str, password: str):
        self.logged_in = True
        return ("OK", [])

    def starttls(self, ssl_context: ssl.SSLContext):
        self.started_tls = True
        return ("OK", [])

    def list(self):
        return ("OK", self._folders)

    def logout(self):
        return ("BYE", [])


@pytest.fixture
def base_env(monkeypatch):
    env = {
        "MCP_ALLOWED_USERS": "alice",
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "1143",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "SMTP_FROM_ADDRESS": "sender@example.com",
        "IMAP_TLS_VERIFY": "true",
        "IMAP_MAX_RETRIES": "2",
        "USER_ALICE_IMAP_USERNAME": "alice-imap",
        "USER_ALICE_IMAP_PASSWORD": "imap-pass",
        "USER_ALICE_SMTP_USERNAME": "alice-smtp",
        "USER_ALICE_SMTP_PASSWORD": "smtp-pass",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_imap_ssl_mode_and_nonstandard_port_used(base_env):
    config = load_config()
    captured = {}

    def fake_ssl_factory(host, port, ssl_context):
        captured["host"] = host
        captured["port"] = port
        captured["context"] = ssl_context
        return FakeImapClient()

    adapter = ImapAdapter(config=config, imap_ssl_factory=fake_ssl_factory)
    client = adapter.connect("alice-imap", "imap-pass")

    assert captured["host"] == "imap.example.com"
    assert captured["port"] == 1143
    assert client.logged_in is True


def test_imap_starttls_upgrade_path_used(base_env, monkeypatch):
    monkeypatch.setenv("IMAP_MODE", "starttls")
    config = load_config()
    client = FakeImapClient()

    def fake_starttls_factory(host, port):
        assert host == "imap.example.com"
        assert port == 1143
        return client

    adapter = ImapAdapter(config=config, imap_starttls_factory=fake_starttls_factory)
    adapter.connect("alice-imap", "imap-pass")

    assert client.started_tls is True
    assert client.logged_in is True


def test_tls_verification_failure_surfaces_secure_error(base_env):
    config = load_config()

    def failing_ssl_factory(host, port, ssl_context):
        raise ssl.SSLError("certificate verify failed")

    adapter = ImapAdapter(config=config, imap_ssl_factory=failing_ssl_factory)
    with pytest.raises(ImapTlsError, match="IMAP TLS verification failed"):
        adapter.connect("alice-imap", "imap-pass")


def test_folder_listing_and_resolution_success(base_env):
    config = load_config()
    adapter = ImapAdapter(config=config)
    folders = adapter.list_folders(FakeImapClient())

    assert folders == ("INBOX", "Sent", "Trash")
    resolved = adapter.resolve_configured_folders(FakeImapClient())
    assert resolved.sent_folder == "Sent"
    assert resolved.trash_folder == "Trash"


def test_configured_folder_missing_fails_deterministically(base_env):
    config = load_config()
    adapter = ImapAdapter(config=config)
    with pytest.raises(FolderResolutionError, match="Configured folders missing on IMAP server: Trash"):
        adapter.resolve_configured_folders(FakeImapClient(folders=[b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Sent"']))


def test_imap_retries_exhausted(base_env):
    config = load_config()

    def always_fails(host, port, ssl_context):
        raise OSError("no route")

    adapter = ImapAdapter(config=config, imap_ssl_factory=always_fails)
    with pytest.raises(ImapConnectionError, match="Unable to establish IMAP connection after retries"):
        adapter.connect("alice-imap", "imap-pass")


def test_imap_tls_verify_must_be_true(base_env, monkeypatch):
    monkeypatch.setenv("IMAP_TLS_VERIFY", "false")
    with pytest.raises(ConfigError, match="IMAP_TLS_VERIFY must be true"):
        load_config()
