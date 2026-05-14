from __future__ import annotations

import re
from email.headerregistry import Address
from email.message import EmailMessage

from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, PermissionDisabledError
from .imap_adapter import ImapAdapter
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

        try:
            smtp_client = self._smtp_adapter.connect(smtp_username, smtp_password)
            smtp_client.send_message(msg)
            smtp_client.quit()
        except SmtpAdapterError as exc:
            raise BackendUnavailableError("SMTP backend unavailable") from exc

        if append_to_sent:
            try:
                imap_client = self._imap_adapter.connect(imap_username, imap_password)
                imap_client.append(self._config.sent_folder, None, None, msg.as_bytes())
                imap_client.logout()
            except Exception as exc:
                raise BackendUnavailableError("Email sent but failed to append to sent folder") from exc
