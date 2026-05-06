from email.message import EmailMessage

import pytest

from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from imap_smtp_mcp.imap_adapter import ImapAdapter
from imap_smtp_mcp.read_tools import ReadOnlyMailboxService


class FakeMailboxClient:
    def __init__(self):
        self.messages = {
            "1": self._build("Hello", "a@example.com", "b@example.com", "body one"),
            "2": self._build_html("Html", "c@example.com", "d@example.com", "<p>Hello <b>world</b></p>"),
        }

    def _build(self, subject, sender, to, body):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to
        msg["Date"] = "Thu, 01 Jan 1970 00:00:00 +0000"
        msg.set_content(body)
        return msg.as_bytes()

    def _build_html(self, subject, sender, to, html):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to
        msg["Date"] = "Thu, 01 Jan 1970 00:00:00 +0000"
        msg.set_content(html, subtype="html")
        return msg.as_bytes()

    def login(self, user, password):
        return ("OK", [])

    def list(self):
        return ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])

    def select(self, folder):
        return ("OK", [b"2"]) if folder == "INBOX" else ("NO", [b""])

    def uid(self, command, *args):
        if command == "search" and args == (None, "TEXT", "hello"):
            return ("OK", [b"1 2"])
        if command == "search" and args == (None, "ALL"):
            return ("OK", [b"1 2"])
        if command == "fetch":
            uid = args[0]
            if uid not in self.messages:
                return ("NO", [None])
            if "HEADER.FIELDS" in args[1]:
                from email import message_from_bytes

                original = message_from_bytes(self.messages[uid])
                hdr = EmailMessage()
                hdr["Subject"] = original["Subject"]
                hdr["From"] = original["From"]
                hdr["Date"] = original["Date"]
                return ("OK", [(b"x", hdr.as_bytes())])
            return ("OK", [(b"x", self.messages[uid])])
        return ("NO", [b""])


@pytest.fixture
def base_env(monkeypatch):
    env = {
        "MCP_ALLOWED_USERS": "alice",
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "IMAP_TLS_VERIFY": "true",
        "IMAP_MAX_RETRIES": "2",
        "ACTION_LIST_FOLDERS": "true",
        "ACTION_SEARCH_EMAILS": "true",
        "ACTION_LIST_EMAILS": "true",
        "ACTION_READ_EMAIL": "true",
        "ACTION_SEND_EMAIL": "true",
        "USER_ALICE_IMAP_USERNAME": "alice-imap",
        "USER_ALICE_IMAP_PASSWORD": "imap-pass",
        "USER_ALICE_SMTP_USERNAME": "alice-smtp",
        "USER_ALICE_SMTP_PASSWORD": "smtp-pass",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def _service(config):
    client = FakeMailboxClient()

    def fake_ssl_factory(host, port, ssl_context):
        return client

    return ReadOnlyMailboxService(ImapAdapter(config=config, imap_ssl_factory=fake_ssl_factory), config=config)


def test_readonly_tools_positive_flows(base_env):
    config = load_config()
    service = _service(config)

    assert service.list_folders("u", "p") == ("INBOX",)
    assert service.search_emails("u", "p", "INBOX", "hello", limit=1) == ("1",)

    listed = service.list_emails("u", "p", "INBOX", offset=0, limit=2)
    assert len(listed) == 2
    assert listed[0].subject == "Hello"

    read = service.read_email("u", "p", "INBOX", "2")
    assert "Hello **world**" in read.body_text


def test_invalid_input_and_not_found(base_env):
    config = load_config()
    service = _service(config)

    with pytest.raises(InvalidInputError, match="query must be single-line"):
        service.search_emails("u", "p", "INBOX", "x\ny")

    with pytest.raises(NotFoundError, match="Folder not found"):
        service.list_emails("u", "p", "Archive")

    with pytest.raises(NotFoundError, match="Email not found"):
        service.read_email("u", "p", "INBOX", "999")


def test_action_flag_blocks_before_network(base_env, monkeypatch):
    monkeypatch.setenv("ACTION_READ_EMAIL", "false")
    config = load_config()
    service = _service(config)
    with pytest.raises(PermissionDisabledError, match="Action disabled: read_email"):
        service.read_email("u", "p", "INBOX", "1")


def test_backend_error_maps_to_stable_mcp_error(base_env):
    config = load_config()

    def failing_ssl_factory(host, port, ssl_context):
        raise OSError("socket error")

    service = ReadOnlyMailboxService(ImapAdapter(config=config, imap_ssl_factory=failing_ssl_factory), config=config)
    with pytest.raises(BackendUnavailableError, match="IMAP backend unavailable"):
        service.list_folders("u", "p")
