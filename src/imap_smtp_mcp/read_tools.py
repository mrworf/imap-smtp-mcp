from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from dataclasses import dataclass
from datetime import date
from email import message_from_bytes
from email.message import Message
from typing import Any

from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from .imap_adapter import ImapAdapter, ImapAdapterError, encode_imap_quoted_string, encode_mailbox_name
from .validation import validate_single_message_uid

MAX_RESULTS = 100
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_UID_SET_RE = re.compile(r"^(\*|[1-9][0-9]*)(:(\*|[1-9][0-9]*))?(,(\*|[1-9][0-9]*)(:(\*|[1-9][0-9]*))?)*$")
_IMAP_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_STRING_CRITERIA = {
    "text": "TEXT",
    "body": "BODY",
    "subject": "SUBJECT",
    "from": "FROM",
    "to": "TO",
    "cc": "CC",
    "bcc": "BCC",
}
_DATE_CRITERIA = {
    "since": "SINCE",
    "before": "BEFORE",
    "on": "ON",
    "sentsince": "SENTSINCE",
    "sentbefore": "SENTBEFORE",
    "senton": "SENTON",
}
_FLAG_CRITERIA = {
    "all": "ALL",
    "new": "NEW",
    "old": "OLD",
    "recent": "RECENT",
    "seen": "SEEN",
    "unseen": "UNSEEN",
    "answered": "ANSWERED",
    "unanswered": "UNANSWERED",
    "deleted": "DELETED",
    "undeleted": "UNDELETED",
    "draft": "DRAFT",
    "undraft": "UNDRAFT",
    "flagged": "FLAGGED",
    "unflagged": "UNFLAGGED",
}


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


def _validate_nonempty_single_line(name: str, value: str) -> str:
    if "\r" in value or "\n" in value:
        raise InvalidInputError(f"{name} must be single-line")
    normalized = value.strip()
    if not normalized:
        raise InvalidInputError(f"{name} must not be empty")
    return normalized


def _search_arguments(criteria: Any) -> tuple[str, ...]:
    args = _compile_criteria(criteria)
    if not args:
        raise InvalidInputError("criteria must not be empty")
    return args


def _compile_criteria(criteria: Any) -> tuple[str, ...]:
    if not isinstance(criteria, dict):
        raise InvalidInputError("criteria must be an object")
    keys = set(criteria)
    logic_keys = keys.intersection({"and", "or", "not"})
    if logic_keys:
        if len(keys) != 1:
            raise InvalidInputError("criteria logic nodes must not include extra fields")
        if "and" in criteria:
            children = criteria["and"]
            if not isinstance(children, list) or not children:
                raise InvalidInputError("criteria and must be a non-empty list")
            out: list[str] = []
            for child in children:
                out.extend(_compile_criteria(child))
            return tuple(out)
        if "or" in criteria:
            children = criteria["or"]
            if not isinstance(children, list) or len(children) != 2:
                raise InvalidInputError("criteria or must contain exactly two operands")
            return ("OR", _criteria_group(_compile_criteria(children[0])), _criteria_group(_compile_criteria(children[1])))
        return ("NOT", _criteria_group(_compile_criteria(criteria["not"])))

    criterion_type = criteria.get("type")
    if not isinstance(criterion_type, str):
        raise InvalidInputError("criteria leaf must include type")
    kind = criterion_type.lower()
    if kind in _STRING_CRITERIA:
        _require_only_fields(criteria, {"type", "value"})
        return (_STRING_CRITERIA[kind], encode_imap_quoted_string(_criteria_text_value(criteria, "value")))
    if kind == "header":
        _require_only_fields(criteria, {"type", "name", "value"})
        name = _criteria_text_value(criteria, "name")
        if not _HEADER_NAME_RE.match(name):
            raise InvalidInputError("criteria header name is invalid")
        return ("HEADER", name, encode_imap_quoted_string(_criteria_text_value(criteria, "value")))
    if kind in _DATE_CRITERIA:
        _require_only_fields(criteria, {"type", "value"})
        return (_DATE_CRITERIA[kind], _criteria_date_value(criteria))
    if kind in _FLAG_CRITERIA:
        _reject_unexpected_value(criteria)
        return (_FLAG_CRITERIA[kind],)
    if kind in {"larger", "smaller"}:
        _require_only_fields(criteria, {"type", "value"})
        return (kind.upper(), _criteria_positive_int(criteria, "value"))
    if kind == "uid":
        _require_only_fields(criteria, {"type", "value"})
        value = _criteria_text_value(criteria, "value")
        if not _UID_SET_RE.match(value):
            raise InvalidInputError("criteria uid must be an IMAP UID set")
        return ("UID", value)
    if kind in {"keyword", "unkeyword"}:
        _require_only_fields(criteria, {"type", "value"})
        value = _criteria_text_value(criteria, "value")
        if not _KEYWORD_RE.match(value):
            raise InvalidInputError("criteria keyword is invalid")
        return (kind.upper(), value)
    raise InvalidInputError(f"criteria type is unsupported: {criterion_type}")


def _criteria_group(args: tuple[str, ...]) -> str:
    if len(args) == 1:
        return args[0]
    return f"({' '.join(args)})"


def _criteria_text_value(criteria: dict[str, Any], name: str) -> str:
    value = criteria.get(name)
    if not isinstance(value, str):
        raise InvalidInputError(f"criteria {name} must be a string")
    if "\r" in value or "\n" in value:
        raise InvalidInputError(f"criteria {name} must be single-line")
    normalized = value.strip()
    if not normalized:
        raise InvalidInputError(f"criteria {name} must not be empty")
    return normalized


def _criteria_date_value(criteria: dict[str, Any]) -> str:
    raw = _criteria_text_value(criteria, "value")
    if not _ISO_DATE_RE.match(raw):
        raise InvalidInputError("criteria date must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise InvalidInputError("criteria date is invalid") from exc
    return f"{parsed.day}-{_IMAP_MONTHS[parsed.month - 1]}-{parsed.year}"


def _criteria_positive_int(criteria: dict[str, Any], name: str) -> str:
    value = criteria.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InvalidInputError(f"criteria {name} must be a positive integer")
    return str(value)


def _reject_unexpected_value(criteria: dict[str, Any]) -> None:
    if set(criteria) != {"type"}:
        raise InvalidInputError("criteria flag leaves must only include type")


def _require_only_fields(criteria: dict[str, Any], allowed: set[str]) -> None:
    extra = set(criteria) - allowed
    if extra:
        raise InvalidInputError(f"criteria contains unsupported field: {sorted(extra)[0]}")


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
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "connect"}) from exc
        try:
            return self._imap_adapter.list_folders(client)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "list"}) from exc

    def search_emails(self, username: str, password: str, folder: str, criteria: Any, limit: int = 50) -> tuple[str, ...]:
        self._enforce_action("search_emails")
        folder_name = _validate_nonempty_single_line("folder", folder)
        if limit <= 0 or limit > MAX_RESULTS:
            raise InvalidInputError(f"limit must be between 1 and {MAX_RESULTS}")
        search_args = _search_arguments(criteria)
        criteria_text = json.dumps(criteria, sort_keys=True, separators=(",", ":"))

        try:
            client = self._imap_adapter.connect(username, password)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "connect", "folder": folder_name, "criteria": criteria_text, "limit": str(limit)}) from exc
        try:
            status, _ = client.select(encode_mailbox_name(folder_name))
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder_name}")
            status, ids = client.uid("search", None, *search_args)
            if status != "OK":
                raise BackendUnavailableError("IMAP search failed", metadata={"imap_phase": "search", "folder": folder_name, "criteria": criteria_text, "limit": str(limit)})
            all_ids = ids[0].decode("utf-8").split() if ids and ids[0] else []
            return tuple(all_ids[:limit])
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "search", "folder": folder_name, "criteria": criteria_text, "limit": str(limit)}) from exc

    def list_emails(self, username: str, password: str, folder: str, offset: int = 0, limit: int = 20) -> tuple[EmailSummary, ...]:
        self._enforce_action("list_emails")
        folder_name = _validate_nonempty_single_line("folder", folder)
        if offset < 0:
            raise InvalidInputError("offset must be >= 0")
        if limit <= 0 or limit > MAX_RESULTS:
            raise InvalidInputError(f"limit must be between 1 and {MAX_RESULTS}")

        try:
            client = self._imap_adapter.connect(username, password)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "connect", "folder": folder_name, "offset": str(offset), "limit": str(limit)}) from exc
        try:
            status, _ = client.select(encode_mailbox_name(folder_name))
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder_name}")

            status, ids = client.uid("search", None, "ALL")
            if status != "OK":
                raise BackendUnavailableError("IMAP list failed", metadata={"imap_phase": "search", "folder": folder_name, "offset": str(offset), "limit": str(limit)})

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
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "fetch", "folder": folder_name, "offset": str(offset), "limit": str(limit)}) from exc

    def read_email(self, username: str, password: str, folder: str, uid: str, max_chars: int = 20000) -> ReadEmailResult:
        self._enforce_action("read_email")
        folder_name = _validate_nonempty_single_line("folder", folder)
        uid_value = validate_single_message_uid("uid", uid)
        if max_chars <= 0:
            raise InvalidInputError("max_chars must be > 0")

        try:
            client = self._imap_adapter.connect(username, password)
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "connect", "folder": folder_name, "uid": uid_value}) from exc
        try:
            status, _ = client.select(encode_mailbox_name(folder_name))
            if status != "OK":
                raise NotFoundError(f"Folder not found: {folder_name}")

            status, data = client.uid("fetch", uid_value, "(RFC822)")
            if status != "OK" or not data or data[0] is None:
                raise NotFoundError(f"Email not found: {uid_value}")

            raw = data[0][1]
            msg = message_from_bytes(raw)
            body = _extract_plain_text(msg)
            if len(body) > max_chars:
                body = body[:max_chars]

            return ReadEmailResult(
                uid=uid_value,
                subject=_decode_header_field(msg, "Subject"),
                from_address=_decode_header_field(msg, "From"),
                to=_decode_header_field(msg, "To"),
                date=_decode_header_field(msg, "Date"),
                body_text=body,
            )
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable", metadata={"imap_phase": "fetch", "folder": folder_name, "uid": uid_value}) from exc
