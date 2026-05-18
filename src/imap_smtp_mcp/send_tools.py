from __future__ import annotations

import re
from email.headerregistry import Address
from email.message import EmailMessage
from typing import Any

from .attachments import (
    AttachmentData,
    decode_attachment_base64,
    normalize_content_type,
    validate_attachment_allowed,
    validate_attachment_filename,
)
from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, PermissionDisabledError
from .imap_adapter import ImapAdapter, encode_mailbox_name
from .smtp_adapter import SmtpAdapter, SmtpAdapterError

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SendEmailService:
    def __init__(self, smtp_adapter: SmtpAdapter, imap_adapter: ImapAdapter, config: AppConfig) -> None:
        self._smtp_adapter = smtp_adapter
        self._imap_adapter = imap_adapter
        self._config = config

    def _enforce_action(self, action: str) -> None:
        try:
            ensure_action_enabled(action, self._config)
        except CapabilityError as exc:
            raise PermissionDisabledError(str(exc)) from exc

    def send_email(
        self,
        smtp_username: str,
        smtp_password: str,
        imap_username: str,
        imap_password: str,
        from_address: str,
        to_addresses: tuple[str, ...],
        subject: str,
        body_text: str,
        from_display_name: str | None = None,
        reply_to_address: str | None = None,
        append_to_sent: bool = True,
        attachments: tuple[AttachmentData, ...] = (),
    ) -> None:
        self._enforce_action("send_email")
        if not EMAIL_PATTERN.match(from_address):
            raise InvalidInputError("invalid from address")
        if reply_to_address and not EMAIL_PATTERN.match(reply_to_address):
            raise InvalidInputError("invalid reply-to address")
        if not to_addresses:
            raise InvalidInputError("at least one recipient is required")
        for to_addr in to_addresses:
            if not EMAIL_PATTERN.match(to_addr):
                raise InvalidInputError(f"invalid recipient address: {to_addr}")
        if len(attachments) > self._config.attachment_policy.max_count:
            raise InvalidInputError(f"at most {self._config.attachment_policy.max_count} attachments are allowed")
        for attachment in attachments:
            validate_attachment_allowed(attachment.filename, attachment.content_type, len(attachment.content), self._config.attachment_policy)

        msg = EmailMessage()
        if from_display_name:
            msg["From"] = str(Address(display_name=from_display_name, addr_spec=from_address))
        else:
            msg["From"] = from_address
        if reply_to_address:
            msg["Reply-To"] = reply_to_address
        msg["To"] = ", ".join(to_addresses)
        msg["Subject"] = subject
        msg.set_content(body_text)
        for attachment in attachments:
            maintype, subtype = attachment.content_type.split("/", 1)
            msg.add_attachment(attachment.content, maintype=maintype, subtype=subtype, filename=attachment.filename)

        try:
            smtp_client = self._smtp_adapter.connect(smtp_username, smtp_password)
            smtp_client.send_message(msg)
            smtp_client.quit()
        except SmtpAdapterError as exc:
            raise BackendUnavailableError("SMTP backend unavailable") from exc

        if append_to_sent:
            try:
                imap_client = self._imap_adapter.connect(imap_username, imap_password)
                imap_client.append(encode_mailbox_name(self._config.sent_folder), None, None, msg.as_bytes())
                imap_client.logout()
            except Exception as exc:
                raise BackendUnavailableError("Email sent but failed to append to sent folder") from exc


def parse_outbound_attachments(raw_attachments: Any, config: AppConfig) -> tuple[AttachmentData, ...]:
    if raw_attachments is None:
        return ()
    if not isinstance(raw_attachments, list):
        raise InvalidInputError("attachments must be an array")
    policy = config.attachment_policy
    if len(raw_attachments) > policy.max_count:
        raise InvalidInputError(f"at most {policy.max_count} attachments are allowed")
    out: list[AttachmentData] = []
    for index, raw in enumerate(raw_attachments):
        if not isinstance(raw, dict):
            raise InvalidInputError(f"attachment {index} must be an object")
        filename_raw = raw.get("filename")
        if not isinstance(filename_raw, str):
            raise InvalidInputError("attachment filename must be a string")
        content_type_raw = raw.get("content_type")
        if not isinstance(content_type_raw, str):
            raise InvalidInputError("attachment content_type is invalid")
        filename = validate_attachment_filename(filename_raw)
        content_type = normalize_content_type(content_type_raw)
        content = decode_attachment_base64(raw.get("content_base64"))
        validate_attachment_allowed(filename, content_type, len(content), policy)
        out.append(AttachmentData(filename=filename, content_type=content_type, content=content))
    return tuple(out)
