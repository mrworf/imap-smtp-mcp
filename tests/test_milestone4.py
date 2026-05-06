from __future__ import annotations

import os
import ssl

import pytest

from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import BackendUnavailableError, InvalidInputError, PermissionDisabledError
from imap_smtp_mcp.imap_adapter import ImapAdapter
from imap_smtp_mcp.send_tools import SendEmailService
from imap_smtp_mcp.smtp_adapter import SmtpAdapter, SmtpTlsError


class FakeSmtpClient:
    def __init__(self) -> None:
        self.started_tls = False
        self.logged_in = False
        self.sent = False

    def starttls(self, *, context):
        self.started_tls = True
        return 220, b"ready"

    def login(self, username, password):
        self.logged_in = True
        return 235, b"ok"

    def send_message(self, message):
        self.sent = True
        return {}

    def quit(self):
        return 221, b"bye"


class FakeImapClient:
    def __init__(self) -> None:
        self.appended = False

    def login(self, user, password):
        return "OK", []

    def append(self, folder, flags, date_time, message):
        self.appended = True
        return "OK", []

    def logout(self):
        return "BYE", []


def _base_env():
    return {
        "MCP_ALLOWED_USERS": "u",
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "465",
        "SMTP_MODE": "ssl",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "SMTP_FROM_ADDRESS": "alice@example.com",
        "USER_U_IMAP_USERNAME": "imap-u",
        "USER_U_IMAP_PASSWORD": "imap-p",
        "USER_U_SMTP_USERNAME": "smtp-u",
        "USER_U_SMTP_PASSWORD": "smtp-p",
        "ACTION_SEND_EMAIL": "true",
    }


@pytest.fixture
def config(monkeypatch):
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    return load_config()


def test_smtp_adapter_ssl_and_port(config):
    seen = {}

    def smtp_ssl_factory(host, port, context):
        seen["host"] = host
        seen["port"] = port
        return FakeSmtpClient()

    adapter = SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory)
    client = adapter.connect("user", "pass")
    assert isinstance(client, FakeSmtpClient)
    assert seen == {"host": "smtp.example.com", "port": 465}


def test_smtp_adapter_starttls(config):
    os.environ["SMTP_MODE"] = "starttls"
    cfg = load_config()
    client = FakeSmtpClient()

    adapter = SmtpAdapter(cfg, smtp_starttls_factory=lambda h, p: client)
    adapter.connect("user", "pass")
    assert client.started_tls


def test_smtp_tls_failure(config):
    def smtp_ssl_factory(host, port, context):
        raise ssl.SSLError("bad cert")

    adapter = SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory)
    with pytest.raises(SmtpTlsError, match="SMTP TLS verification failed"):
        adapter.connect("u", "p")


def test_send_email_flag_blocked(config):
    os.environ["ACTION_SEND_EMAIL"] = "false"
    cfg = load_config()
    service = SendEmailService(SmtpAdapter(cfg, smtp_ssl_factory=lambda *_: FakeSmtpClient()), ImapAdapter(cfg), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: send_email"):
        service.send_email("u", "p", ("bob@example.com",), "s", "b")


def test_send_email_append_default_and_disable(config):
    smtp_client = FakeSmtpClient()
    imap_client = FakeImapClient()
    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_: smtp_client),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, c: imap_client),
        config,
    )
    service.send_email("u", "p", ("bob@example.com",), "Hello", "Body")
    assert smtp_client.sent
    assert imap_client.appended

    imap_client2 = FakeImapClient()
    service2 = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_: FakeSmtpClient()),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, c: imap_client2),
        config,
    )
    service2.send_email("u", "p", ("bob@example.com",), "Hello", "Body", append_to_sent=False)
    assert not imap_client2.appended


def test_send_email_append_failure_is_clear(config):
    class BrokenImap(FakeImapClient):
        def append(self, folder, flags, date_time, message):
            raise RuntimeError("append failed")

    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_: FakeSmtpClient()),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, c: BrokenImap()),
        config,
    )
    with pytest.raises(BackendUnavailableError, match="Email sent but failed to append to sent folder"):
        service.send_email("u", "p", ("bob@example.com",), "Hello", "Body")


def test_send_email_invalid_addresses(config):
    os.environ["SMTP_FROM_ADDRESS"] = "nope"
    bad_from_cfg = load_config()
    service = SendEmailService(
        SmtpAdapter(bad_from_cfg, smtp_ssl_factory=lambda *_: FakeSmtpClient()),
        ImapAdapter(bad_from_cfg),
        bad_from_cfg,
    )
    with pytest.raises(InvalidInputError, match="invalid from address"):
        service.send_email("u", "p", ("bob@example.com",), "s", "b")

    service = SendEmailService(SmtpAdapter(config, smtp_ssl_factory=lambda *_: FakeSmtpClient()), ImapAdapter(config), config)
    with pytest.raises(InvalidInputError, match="invalid recipient address"):
        service.send_email("u", "p", ("bad",), "s", "b")


def test_send_email_smtp_failure_maps_backend_unavailable(config):
    def smtp_ssl_factory(*_):
        raise OSError("down")

    service = SendEmailService(SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory), ImapAdapter(config), config)
    with pytest.raises(BackendUnavailableError, match="SMTP backend unavailable"):
        service.send_email("u", "p", ("bob@example.com",), "s", "b")


def test_send_email_uses_from_display_name(config):
    os.environ["SMTP_FROM_DISPLAY_NAME"] = "Alice Sender"
    cfg = load_config()
    smtp_client = FakeSmtpClient()
    service = SendEmailService(
        SmtpAdapter(cfg, smtp_ssl_factory=lambda *_: smtp_client),
        ImapAdapter(cfg, imap_ssl_factory=lambda h, p, c: FakeImapClient()),
        cfg,
    )
    service.send_email("u", "p", ("bob@example.com",), "Subject", "Body")
    assert smtp_client.sent
