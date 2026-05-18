from email.message import EmailMessage

import pytest

from imap_smtp_mcp.attachments import encode_attachment_base64
from imap_smtp_mcp.config import load_config
from imap_smtp_mcp.errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from imap_smtp_mcp.imap_adapter import ImapAdapter, encode_imap_quoted_string, encode_mailbox_name
from imap_smtp_mcp.read_tools import ReadOnlyMailboxService
from imap_smtp_mcp.tool_controller import TOOL_SCHEMAS


class FakeMailboxClient:
    def __init__(self):
        self.uid_calls = []
        self.selected_folders = []
        self.messages = {
            "1": self._build("Hello", "a@example.com", "b@example.com", "body one"),
            "2": self._build_html("Html", "c@example.com", "d@example.com", "<p>Hello <b>world</b></p>"),
            "3": self._build_html(
                "Noisy Html",
                "noise@example.com",
                "d@example.com",
                """
                <html>
                  <head>
                    <title>hidden title</title>
                    <style>.secret { color: red; }</style>
                    <script>window.alert("nope");</script>
                    <link href="tracker.css">
                    <meta name="tracking" content="hidden">
                  </head>
                  <body>
                    <p>Hello <strong>visible</strong> text</p>
                    <div>Second line<script>console.log("hidden")</script></div>
                    <template>template tracking text</template>
                    <noscript>noscript fallback tracking text</noscript>
                    <svg><text>svg tracking text</text></svg>
                    <canvas>canvas tracking text</canvas>
                    <iframe>iframe tracking text</iframe>
                  </body>
                </html>
                """,
            ),
            "4": self._build_multipart_alternative(
                "Multipart",
                "plain@example.com",
                "d@example.com",
                "plain body wins",
                "<html><body><p>HTML fallback</p><script>console.log('hidden')</script></body></html>",
            ),
            "5": self._build_html(
                "Headings",
                "headings@example.com",
                "d@example.com",
                "<h1>Main</h1><p>Intro</p><h3>Details</h3><h6>Fine print</h6>",
            ),
            "6": self._build_with_attachments(),
            "7": self._build_with_oversized_attachment(),
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

    def _build_multipart_alternative(self, subject, sender, to, text, html):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to
        msg["Date"] = "Thu, 01 Jan 1970 00:00:00 +0000"
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
        return msg.as_bytes()

    def _build_with_attachments(self):
        msg = EmailMessage()
        msg["Subject"] = "Attachments"
        msg["From"] = "files@example.com"
        msg["To"] = "d@example.com"
        msg["Date"] = "Thu, 01 Jan 1970 00:00:00 +0000"
        msg.set_content("body with files")
        msg.add_attachment(b"hello attachment", maintype="text", subtype="plain", filename="note.txt")
        msg.add_attachment(b"<script>bad()</script>", maintype="text", subtype="html", filename="page.html")
        msg.add_attachment(b"alert(1)", maintype="application", subtype="octet-stream", filename="SCRIPT.JS")
        return msg.as_bytes()

    def _build_with_oversized_attachment(self):
        msg = EmailMessage()
        msg["Subject"] = "Big"
        msg["From"] = "files@example.com"
        msg["To"] = "d@example.com"
        msg["Date"] = "Thu, 01 Jan 1970 00:00:00 +0000"
        msg.set_content("body with big file")
        msg.add_attachment(b"x" * 20, maintype="text", subtype="plain", filename="big.txt")
        return msg.as_bytes()

    def login(self, user, password):
        return ("OK", [])

    def list(self):
        return ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])

    def select(self, folder):
        self.selected_folders.append(folder)
        if folder in {encode_mailbox_name("INBOX"), encode_mailbox_name("MCP Smoke Folder")}:
            return ("OK", [b"2"])
        return ("NO", [b""])

    def uid(self, command, *args):
        self.uid_calls.append((command, args))
        if command == "search" and args == (None, "TEXT", encode_imap_quoted_string("hello")):
            return ("OK", [b"1 2"])
        if command == "search" and args == (None, "TEXT", encode_imap_quoted_string("hello SINCE yesterday")):
            return ("OK", [b"2"])
        if command == "search" and args == (None, "SINCE", "13-May-2026", "BEFORE", "14-May-2026"):
            return ("OK", [b"2"])
        if command == "search" and args == (None, "ALL"):
            return ("OK", [b"1 2"])
        if command == "search" and args[:1] == (None,):
            return ("OK", [b"1"])
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
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_MODE": "ssl",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_MODE": "starttls",
        "IMAP_SENT_FOLDER": "Sent",
        "IMAP_TRASH_FOLDER": "Trash",
        "AUDIT_LOG_DIR": "/tmp/imap-smtp-audit",
        "OAUTH_DEV_INSECURE_SECRETS": "true",
        "IMAP_TLS_VERIFY": "true",
        "IMAP_MAX_RETRIES": "2",
        "ACTION_LIST_FOLDERS": "true",
        "ACTION_SEARCH_EMAILS": "true",
        "ACTION_LIST_EMAILS": "true",
        "ACTION_READ_EMAIL": "true",
        "ACTION_SEND_EMAIL": "true",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def _service(config):
    client = FakeMailboxClient()

    def fake_ssl_factory(host, port, ssl_context):
        return client

    return ReadOnlyMailboxService(ImapAdapter(config=config, imap_ssl_factory=fake_ssl_factory), config=config)


def _service_with_client(config):
    client = FakeMailboxClient()

    def fake_ssl_factory(host, port, ssl_context):
        return client

    return ReadOnlyMailboxService(ImapAdapter(config=config, imap_ssl_factory=fake_ssl_factory), config=config), client


def test_readonly_tools_positive_flows(base_env):
    config = load_config()
    service = _service(config)

    assert service.list_folders("u", "p") == ("INBOX",)
    assert service.search_emails("u", "p", "INBOX", {"type": "text", "value": "hello"}, limit=1) == ("1",)

    listed = service.list_emails("u", "p", "INBOX", offset=0, limit=2)
    assert len(listed) == 2
    assert listed[0].subject == "Hello"

    read = service.read_email("u", "p", "INBOX", "2")
    assert "Hello **world**" in read.body_text


def test_read_email_strips_non_visible_html_content(base_env):
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "3")

    assert "Hello **visible** text" in read.body_text
    assert "Second line" in read.body_text
    for hidden in (
        ".secret",
        "color: red",
        "window.alert",
        "console.log",
        "hidden title",
        "template tracking text",
        "noscript fallback tracking text",
        "svg tracking text",
        "canvas tracking text",
        "iframe tracking text",
        "<script",
        "<style",
    ):
        assert hidden not in read.body_text


def test_read_email_prefers_plain_text_over_html_fallback(base_env):
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "4")

    assert read.body_text == "plain body wins"
    assert "HTML fallback" not in read.body_text
    assert "console.log" not in read.body_text


def test_read_email_converts_html_headings_to_markdown(base_env):
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "5")

    assert read.body_text == "# Main\n\nIntro\n\n### Details\n\n###### Fine print"


def test_search_emails_uses_structured_text_criteria(base_env):
    config = load_config()
    service, client = _service_with_client(config)

    assert service.search_emails("u", "p", "INBOX", {"type": "text", "value": "hello"}, limit=2) == ("1", "2")

    assert ("search", (None, "TEXT", encode_imap_quoted_string("hello"))) in client.uid_calls


def test_search_emails_accepts_structured_date_criteria(base_env):
    config = load_config()
    service, client = _service_with_client(config)

    result = service.search_emails(
        "u",
        "p",
        "INBOX",
        {"and": [{"type": "since", "value": "2026-05-13"}, {"type": "before", "value": "2026-05-14"}]},
    )

    assert result == ("2",)
    assert ("search", (None, "SINCE", "13-May-2026", "BEFORE", "14-May-2026")) in client.uid_calls


def test_read_tools_quote_folder_names_with_spaces(base_env):
    config = load_config()
    service, client = _service_with_client(config)

    assert service.search_emails("u", "p", "MCP Smoke Folder", {"type": "text", "value": "hello"}, limit=1) == ("1",)

    assert client.selected_folders == [encode_mailbox_name("MCP Smoke Folder")]


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        ({"type": "text", "value": "hello world"}, ("TEXT", encode_imap_quoted_string("hello world"))),
        ({"type": "subject", "value": 'quote " marker'}, ("SUBJECT", encode_imap_quoted_string('quote " marker'))),
        ({"type": "body", "value": "slash \\ marker"}, ("BODY", encode_imap_quoted_string("slash \\ marker"))),
        ({"type": "from", "value": "alice@example.com"}, ("FROM", encode_imap_quoted_string("alice@example.com"))),
        ({"type": "to", "value": "bob@example.com"}, ("TO", encode_imap_quoted_string("bob@example.com"))),
        ({"type": "cc", "value": "team@example.com"}, ("CC", encode_imap_quoted_string("team@example.com"))),
        ({"type": "bcc", "value": "hidden@example.com"}, ("BCC", encode_imap_quoted_string("hidden@example.com"))),
        ({"type": "header", "name": "Message-ID", "value": "abc 123"}, ("HEADER", "Message-ID", encode_imap_quoted_string("abc 123"))),
        ({"type": "on", "value": "2026-05-15"}, ("ON", "15-May-2026")),
        ({"type": "sentsince", "value": "2026-05-15"}, ("SENTSINCE", "15-May-2026")),
        ({"type": "sentbefore", "value": "2026-05-15"}, ("SENTBEFORE", "15-May-2026")),
        ({"type": "senton", "value": "2026-05-15"}, ("SENTON", "15-May-2026")),
        ({"type": "seen"}, ("SEEN",)),
        ({"type": "unseen"}, ("UNSEEN",)),
        ({"type": "answered"}, ("ANSWERED",)),
        ({"type": "deleted"}, ("DELETED",)),
        ({"type": "draft"}, ("DRAFT",)),
        ({"type": "flagged"}, ("FLAGGED",)),
        ({"type": "larger", "value": 1024}, ("LARGER", "1024")),
        ({"type": "smaller", "value": 2048}, ("SMALLER", "2048")),
        ({"type": "uid", "value": "1,3:5,*"}, ("UID", "1,3:5,*")),
        ({"type": "keyword", "value": "important"}, ("KEYWORD", "important")),
        ({"type": "unkeyword", "value": "important"}, ("UNKEYWORD", "important")),
    ],
)
def test_search_emails_compiles_supported_leaf_criteria(base_env, criteria, expected):
    config = load_config()
    service, client = _service_with_client(config)

    assert service.search_emails("u", "p", "INBOX", criteria) == ("1",)

    assert ("search", (None, *expected)) in client.uid_calls


def test_search_emails_compiles_logic_criteria(base_env):
    config = load_config()
    service, client = _service_with_client(config)

    criteria = {
        "and": [
            {"type": "text", "value": "marker"},
            {"or": [{"type": "from", "value": "a@example.com"}, {"type": "to", "value": "b@example.com"}]},
            {"not": {"type": "deleted"}},
        ]
    }

    assert service.search_emails("u", "p", "INBOX", criteria) == ("1",)

    assert (
        "search",
        (
            None,
            "TEXT",
            encode_imap_quoted_string("marker"),
            "OR",
            f"(FROM {encode_imap_quoted_string('a@example.com')})",
            f"(TO {encode_imap_quoted_string('b@example.com')})",
            "NOT",
            "DELETED",
        ),
    ) in client.uid_calls


@pytest.mark.parametrize(
    ("criteria", "message"),
    [
        ("hello", "criteria must be an object"),
        ({}, "criteria leaf must include type"),
        ({"type": "bogus"}, "unsupported"),
        ({"type": "text"}, "value must be a string"),
        ({"type": "text", "value": " \t"}, "value must not be empty"),
        ({"type": "text", "value": "x\ny"}, "value must be single-line"),
        ({"type": "since", "value": "13-May-2026"}, "YYYY-MM-DD"),
        ({"type": "since", "value": "2026-02-31"}, "date is invalid"),
        ({"type": "uid", "value": "0"}, "UID set"),
        ({"type": "larger", "value": 0}, "positive integer"),
        ({"type": "larger", "value": "10"}, "positive integer"),
        ({"type": "header", "name": "Bad Header", "value": "x"}, "header name"),
        ({"type": "keyword", "value": "bad flag"}, "keyword"),
        ({"type": "seen", "value": "x"}, "flag leaves"),
        ({"and": []}, "non-empty list"),
        ({"or": [{"type": "seen"}]}, "exactly two operands"),
        ({"not": {"type": "seen"}, "type": "text"}, "logic nodes"),
    ],
)
def test_search_emails_rejects_invalid_structured_criteria_before_imap(base_env, criteria, message):
    config = load_config()
    service, client = _service_with_client(config)

    with pytest.raises(InvalidInputError, match=message):
        service.search_emails("u", "p", "INBOX", criteria)

    assert client.uid_calls == []
    assert client.selected_folders == []


def test_search_emails_schema_documents_structured_criteria():
    schema = TOOL_SCHEMAS["search_emails"]
    criteria = schema["properties"]["criteria"]
    criteria_def = schema["$defs"]["searchCriteria"]
    description = criteria["description"]
    variants = criteria_def["anyOf"]

    assert schema["required"] == ["folder", "criteria"]
    assert schema["additionalProperties"] is False
    assert criteria == {"$ref": "#/$defs/searchCriteria", "description": description}
    assert criteria_def.get("additionalProperties") is not True
    assert "Structured IMAP SEARCH expression" in description
    assert "exact marker searches" in description
    assert "subject, body, and full message text" in description
    assert "String values are safely quoted" in description
    assert "{'type':'text','value':'MCP-SMOKE-...'}" in description

    encoded = str(variants)
    for marker in (
        "'text'",
        "'subject'",
        "'since'",
        "'unseen'",
        "'header'",
        "'uid'",
        "'and'",
        "'or'",
        "'not'",
    ):
        assert marker in encoded

    assert "'additionalProperties': True" not in encoded


def test_invalid_input_and_not_found(base_env):
    config = load_config()
    service = _service(config)

    with pytest.raises(InvalidInputError, match="folder must be single-line"):
        service.search_emails("u", "p", "IN\nBOX", {"type": "text", "value": "hello"})

    with pytest.raises(InvalidInputError, match="uid must be single-line"):
        service.read_email("u", "p", "INBOX", "1\r")

    with pytest.raises(InvalidInputError, match="limit must be between 1 and 100"):
        service.search_emails("u", "p", "INBOX", {"type": "text", "value": "hello"}, limit=101)

    with pytest.raises(InvalidInputError, match="offset must be >= 0"):
        service.list_emails("u", "p", "INBOX", offset=-1)

    with pytest.raises(NotFoundError, match="Folder not found"):
        service.list_emails("u", "p", "Archive")

    with pytest.raises(NotFoundError, match="Email not found"):
        service.read_email("u", "p", "INBOX", "999")


@pytest.mark.parametrize("uid", ["1:*", "1,2", "1:5", "*", "0", "-1", "+1", " "])
def test_read_email_rejects_sequence_set_uids_before_imap(base_env, uid):
    config = load_config()
    service, client = _service_with_client(config)

    with pytest.raises(InvalidInputError, match="uid must"):
        service.read_email("u", "p", "INBOX", uid)

    assert client.uid_calls == []


def test_read_email_safe_truncation(base_env):
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "1", max_chars=4)
    assert read.body_text == "body"


def test_read_email_lists_attachment_metadata_and_block_reasons(base_env):
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "6")

    assert read.body_text == "body with files"
    assert len(read.attachments) == 3
    allowed = read.attachments[0]
    assert allowed.attachment_id == "part-2"
    assert allowed.filename == "note.txt"
    assert allowed.content_type == "text/plain"
    assert allowed.size_bytes == len(b"hello attachment")
    assert allowed.retrievable is True
    assert allowed.blocked_reason is None
    assert read.attachments[1].blocked_reason == "blocked_mime_type"
    assert read.attachments[2].blocked_reason == "blocked_extension"


def test_get_email_attachment_returns_allowed_base64_content(base_env):
    config = load_config()
    service = _service(config)

    attachment = service.get_email_attachment("u", "p", "INBOX", "6", "part-2")

    assert attachment.filename == "note.txt"
    assert attachment.content_type == "text/plain"
    assert attachment.size_bytes == len(b"hello attachment")
    assert attachment.content_base64 == encode_attachment_base64(b"hello attachment")


def test_get_email_attachment_blocks_dangerous_or_missing_attachment(base_env):
    config = load_config()
    service, client = _service_with_client(config)

    with pytest.raises(InvalidInputError, match="blocked by MIME type"):
        service.get_email_attachment("u", "p", "INBOX", "6", "part-3")
    with pytest.raises(InvalidInputError, match="blocked by extension"):
        service.get_email_attachment("u", "p", "INBOX", "6", "part-4")
    with pytest.raises(NotFoundError, match="Attachment not found"):
        service.get_email_attachment("u", "p", "INBOX", "6", "part-999")

    assert client.uid_calls


def test_get_email_attachment_blocks_oversized_content(base_env, monkeypatch):
    monkeypatch.setenv("MCP_ATTACHMENT_MAX_BYTES", "4")
    config = load_config()
    service = _service(config)

    read = service.read_email("u", "p", "INBOX", "7")
    assert read.attachments[0].blocked_reason == "oversized"

    with pytest.raises(InvalidInputError, match="attachment exceeds maximum size"):
        service.get_email_attachment("u", "p", "INBOX", "7", "part-2")


def test_action_flag_blocks_before_network(base_env, monkeypatch):
    monkeypatch.setenv("ACTION_READ_EMAIL", "false")
    config = load_config()
    service, client = _service_with_client(config)
    with pytest.raises(PermissionDisabledError, match="Action disabled: read_email"):
        service.read_email("u", "p", "INBOX", "1")
    with pytest.raises(PermissionDisabledError, match="Action disabled: read_email"):
        service.get_email_attachment("u", "p", "INBOX", "6", "part-2")
    assert client.uid_calls == []


def test_backend_error_maps_to_stable_mcp_error(base_env):
    config = load_config()

    def failing_ssl_factory(host, port, ssl_context):
        raise OSError("socket error")

    service = ReadOnlyMailboxService(ImapAdapter(config=config, imap_ssl_factory=failing_ssl_factory), config=config)
    with pytest.raises(BackendUnavailableError, match="IMAP backend unavailable") as list_exc:
        service.list_folders("u", "p")
    assert list_exc.value.metadata == {"imap_phase": "connect"}
    with pytest.raises(BackendUnavailableError, match="IMAP backend unavailable") as search_exc:
        service.search_emails("u", "p", "INBOX", {"type": "text", "value": "hello"})
    assert search_exc.value.metadata == {"imap_phase": "connect", "folder": "INBOX", "criteria": '{"type":"text","value":"hello"}', "limit": "50"}
