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
        self.sent_message = None

    def starttls(self, *, context):
        self.started_tls = True
        return 220, b"ready"

    def login(self, username, password):
        self.logged_in = True
        return 235, b"ok"

    def send_message(self, message):
        self.sent = True
        self.sent_message = message
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
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "465",
        "SMTP_MODE": "ssl",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": "/tmp/imap-smtp-audit",
        "ACTION_SEND_EMAIL": "true",
    }


@pytest.fixture
def config(monkeypatch):
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    return load_config()


def test_smtp_adapter_ssl_and_port(config):
    seen = {}

    def smtp_ssl_factory(host, port, *, timeout, context):
        seen["host"] = host
        seen["port"] = port
        seen["timeout"] = timeout
        seen["context"] = context
        return FakeSmtpClient()

    adapter = SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory)
    client = adapter.connect("user", "pass")
    assert isinstance(client, FakeSmtpClient)
    assert seen["host"] == "smtp.example.com"
    assert seen["port"] == 465
    assert seen["timeout"] == 30
    assert isinstance(seen["context"], ssl.SSLContext)


def test_smtp_adapter_starttls(config):
    os.environ["SMTP_MODE"] = "starttls"
    cfg = load_config()
    client = FakeSmtpClient()

    seen = {}

    def starttls_factory(host, port, *, timeout):
        seen["host"] = host
        seen["port"] = port
        seen["timeout"] = timeout
        return client

    adapter = SmtpAdapter(cfg, smtp_starttls_factory=starttls_factory)
    adapter.connect("user", "pass")
    assert client.started_tls
    assert seen == {"host": "smtp.example.com", "port": 465, "timeout": 30}


def test_smtp_timeout_must_be_positive(monkeypatch):
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SMTP_TIMEOUT_SECONDS", "0")

    with pytest.raises(ValueError, match="SMTP_TIMEOUT_SECONDS must be > 0"):
        load_config()


def test_smtp_tls_failure(config):
    def smtp_ssl_factory(host, port, *, timeout, context):
        raise ssl.SSLError("bad cert")

    adapter = SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory)
    with pytest.raises(SmtpTlsError, match="SMTP TLS verification failed"):
        adapter.connect("u", "p")


def test_send_email_flag_blocked(config):
    os.environ["ACTION_SEND_EMAIL"] = "false"
    cfg = load_config()
    service = SendEmailService(SmtpAdapter(cfg, smtp_ssl_factory=lambda *_args, **_kwargs: FakeSmtpClient()), ImapAdapter(cfg), cfg)
    with pytest.raises(PermissionDisabledError, match="Action disabled: send_email"):
        service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "s", "b")


def test_send_email_append_default_and_disable(config):
    smtp_client = FakeSmtpClient()
    imap_client = FakeImapClient()
    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: smtp_client),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, *, ssl_context: imap_client),
        config,
    )
    service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "Hello", "Body")
    assert smtp_client.sent
    assert imap_client.appended

    imap_client2 = FakeImapClient()
    service2 = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: FakeSmtpClient()),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, *, ssl_context: imap_client2),
        config,
    )
    service2.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "Hello", "Body", append_to_sent=False)
    assert not imap_client2.appended


def test_send_email_append_failure_is_clear(config):
    class BrokenImap(FakeImapClient):
        def append(self, folder, flags, date_time, message):
            raise RuntimeError("append failed")

    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: FakeSmtpClient()),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, *, ssl_context: BrokenImap()),
        config,
    )
    with pytest.raises(BackendUnavailableError, match="Email sent but failed to append to sent folder"):
        service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "Hello", "Body")


def test_send_email_invalid_addresses(config):
    service = SendEmailService(SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: FakeSmtpClient()), ImapAdapter(config), config)
    with pytest.raises(InvalidInputError, match="invalid from address"):
        service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "nope", ("bob@example.com",), "s", "b")
    with pytest.raises(InvalidInputError, match="invalid recipient address"):
        service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bad",), "s", "b")


def test_send_email_smtp_failure_maps_backend_unavailable(config):
    def smtp_ssl_factory(*_args, **_kwargs):
        raise OSError("down")

    service = SendEmailService(SmtpAdapter(config, smtp_ssl_factory=smtp_ssl_factory), ImapAdapter(config), config)
    with pytest.raises(BackendUnavailableError, match="SMTP backend unavailable"):
        service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "s", "b")




def test_send_email_uses_separate_imap_and_smtp_credentials(config):
    seen = {}

    class CapturingSmtpClient(FakeSmtpClient):
        pass

    def smtp_factory(*_args, **_kwargs):
        return CapturingSmtpClient()

    class CapturingImapClient(FakeImapClient):
        def login(self, user, password):
            seen["imap_user"] = user
            seen["imap_pass"] = password
            return super().login(user, password)

    def imap_factory(host, port, *, ssl_context):
        return CapturingImapClient()

    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=smtp_factory),
        ImapAdapter(config, imap_ssl_factory=imap_factory),
        config,
    )

    service.send_email(
        "smtp-username",
        "smtp-password",
        "imap-username",
        "imap-password",
        "alice@example.com",
        ("bob@example.com",),
        "Subject",
        "Body",
    )

    assert seen == {"imap_user": "imap-username", "imap_pass": "imap-password"}
def test_send_email_uses_from_display_name(config):
    smtp_client = FakeSmtpClient()
    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: smtp_client),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()),
        config,
    )
    service.send_email("smtp-u", "smtp-p", "imap-u", "imap-p", "alice@example.com", ("bob@example.com",), "Subject", "Body", from_display_name="Alice Sender")
    assert smtp_client.sent
    assert smtp_client.sent_message["From"] == "Alice Sender <alice@example.com>"
    assert "Reply-To" not in smtp_client.sent_message


def test_send_email_sets_reply_to_when_requested(config):
    smtp_client = FakeSmtpClient()
    service = SendEmailService(
        SmtpAdapter(config, smtp_ssl_factory=lambda *_args, **_kwargs: smtp_client),
        ImapAdapter(config, imap_ssl_factory=lambda h, p, *, ssl_context: FakeImapClient()),
        config,
    )
    service.send_email(
        "smtp-u",
        "smtp-p",
        "imap-u",
        "imap-p",
        "alice@example.com",
        ("bob@example.com",),
        "Subject",
        "Body",
        from_display_name="Alice Sender",
        reply_to_address="alice@example.com",
    )
    assert smtp_client.sent_message["Reply-To"] == "alice@example.com"
