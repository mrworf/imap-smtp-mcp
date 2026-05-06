from __future__ import annotations

import imaplib
from html.parser import HTMLParser
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message

from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from .imap_adapter import ImapAdapter, ImapAdapterError

MAX_RESULTS = 100


@dataclass(frozen=True)
class EmailSummary:
    uid: str
    subject: str
    from_address: str
    date: str


@dataclass(frozen=True)
class ReadEmailResult:
    uid: str
    subject: str
    from_address: str
    to: str
    date: str
    body_text: str


def _decode_header_field(message: Message, field: str) -> str:
    return str(message.get(field, "")).strip()


def _extract_plain_text(msg: Message) -> str:
    if msg.is_multipart():
        html_candidate = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            if ctype == "text/plain" and text.strip():
                return text.strip()
            if ctype == "text/html" and text.strip() and not html_candidate:
                html_candidate = text
        if html_candidate:
            return _html_to_markdown(html_candidate).strip()
        return ""

    payload = msg.get_payload(decode=True) or b""
    text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    if msg.get_content_type() == "text/html":
        return _html_to_markdown(text).strip()
    return text.strip()


class _SimpleMarkdownHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in {"p", "br", "div"}:
            self.parts.append("\n")
        if tag in {"b", "strong"}:
            self.parts.append("**")

    def handle_endtag(self, tag):
        if tag in {"b", "strong"}:
            self.parts.append("**")
        if tag in {"p", "div"}:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def _html_to_markdown(value: str) -> str:
    parser = _SimpleMarkdownHTMLParser()
    parser.feed(value)
    return "".join(parser.parts)


class ReadOnlyMailboxService:
    def __init__(self, imap_adapter: ImapAdapter, config: AppConfig | None = None) -> None:
        self._imap_adapter = imap_adapter
        self._config = config

    def _enforce_action(self, action: str) -> None:
        if self._config is None:
            return
        try:
            ensure_action_enabled(action, self._config)
        except CapabilityError as exc:
            raise PermissionDisabledError(str(exc)) from exc

    def list_folders(self, username: str, password: str) -> tuple[str, ...]:
        self._enforce_action("list_folders")
        try:
            client = self._imap_adapter.connect(username, password)
            return self._imap_adapter.list_folders(client)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def search_emails(self, username: str, password: str, folder: str, query: str, limit: int = 50) -> tuple[str, ...]:
        self._enforce_action("search_emails")
        if not folder.strip():
            raise InvalidInputError("folder must not be empty")
        if not query.strip():
            raise InvalidInputError("query must not be empty")
        if limit <= 0 or limit > MAX_RESULTS:
            raise InvalidInputError(f"limit must be between 1 and {MAX_RESULTS}")
        if "\r" in query or "\n" in query:
            raise InvalidInputError("query must be single-line")

        client = self._imap_adapter.connect(username, password)
        try:
            status, _ = client.select(folder)
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder}")
            status, ids = client.uid("search", None, "TEXT", query)
            if status != "OK":
                raise BackendUnavailableError("IMAP search failed")
            all_ids = ids[0].decode("utf-8").split() if ids and ids[0] else []
            return tuple(all_ids[:limit])
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def list_emails(self, username: str, password: str, folder: str, offset: int = 0, limit: int = 20) -> tuple[EmailSummary, ...]:
        self._enforce_action("list_emails")
        if not folder.strip():
            raise InvalidInputError("folder must not be empty")
        if offset < 0:
            raise InvalidInputError("offset must be >= 0")
        if limit <= 0 or limit > MAX_RESULTS:
            raise InvalidInputError(f"limit must be between 1 and {MAX_RESULTS}")

        try:
            client = self._imap_adapter.connect(username, password)
            status, _ = client.select(folder)
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder}")

            status, ids = client.uid("search", None, "ALL")
            if status != "OK":
                raise BackendUnavailableError("IMAP list failed")

            all_ids = ids[0].decode("utf-8").split() if ids and ids[0] else []
            window = all_ids[offset : offset + limit]
            out: list[EmailSummary] = []
            for uid in window:
                status, data = client.uid("fetch", uid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
                if status != "OK" or not data or data[0] is None:
                    continue
                raw_header = data[0][1]
                msg = message_from_bytes(raw_header)
                out.append(
                    EmailSummary(uid=uid, subject=_decode_header_field(msg, "Subject"), from_address=_decode_header_field(msg, "From"), date=_decode_header_field(msg, "Date"))
                )
            return tuple(out)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def read_email(self, username: str, password: str, folder: str, uid: str, max_chars: int = 20000) -> ReadEmailResult:
        self._enforce_action("read_email")
        if not folder.strip():
            raise InvalidInputError("folder must not be empty")
        if not uid.strip():
            raise InvalidInputError("uid must not be empty")
        if max_chars <= 0:
            raise InvalidInputError("max_chars must be > 0")

        try:
            client = self._imap_adapter.connect(username, password)
            status, _ = client.select(folder)
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder}")

            status, data = client.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not data or data[0] is None:
                raise NotFoundError(f"Email not found: {uid}")

            raw = data[0][1]
            msg = message_from_bytes(raw)
            body = _extract_plain_text(msg)
            if len(body) > max_chars:
                body = body[:max_chars]

            return ReadEmailResult(
                uid=uid,
                subject=_decode_header_field(msg, "Subject"),
                from_address=_decode_header_field(msg, "From"),
                to=_decode_header_field(msg, "To"),
                date=_decode_header_field(msg, "Date"),
                body_text=body,
            )
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc
