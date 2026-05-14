from __future__ import annotations

import smtplib
import socket
import ssl
from collections.abc import Callable
from email.message import EmailMessage

from .config import AppConfig, ProtocolMode


class SmtpAdapterError(RuntimeError):
    """Base error for SMTP adapter failures."""


class SmtpTlsError(SmtpAdapterError):
    """Raised when SMTP TLS handshake or cert validation fails."""


class SmtpConnectionError(SmtpAdapterError):
    """Raised when SMTP connection or auth fails."""


class SmtpClient:
    def login(self, username: str, password: str) -> tuple[int, bytes]: ...

    def send_message(self, message: EmailMessage) -> dict[str, tuple[int, bytes]]: ...

    def starttls(self, *, context: ssl.SSLContext) -> tuple[int, bytes]: ...

    def quit(self) -> tuple[int, bytes]: ...


SmtpSslFactory = Callable[..., SmtpClient]
SmtpStartTlsFactory = Callable[..., SmtpClient]


class SmtpAdapter:
    def __init__(
        self,
        config: AppConfig,
        ssl_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        smtp_ssl_factory: SmtpSslFactory = smtplib.SMTP_SSL,
        smtp_starttls_factory: SmtpStartTlsFactory = smtplib.SMTP,
    ) -> None:
        self._config = config
        self._ssl_factory = ssl_factory
        self._smtp_ssl_factory = smtp_ssl_factory
        self._smtp_starttls_factory = smtp_starttls_factory

    def create_ssl_context(self) -> ssl.SSLContext:
        context = self._ssl_factory()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def connect(self, username: str, password: str) -> SmtpClient:
        context = self.create_ssl_context()
        try:
            if self._config.smtp.mode == ProtocolMode.SSL:
                client = self._smtp_ssl_factory(
                    self._config.smtp.host,
                    self._config.smtp.port,
                    timeout=self._config.smtp_timeout_seconds,
                    context=context,
                )
            else:
                client = self._smtp_starttls_factory(
                    self._config.smtp.host,
                    self._config.smtp.port,
                    timeout=self._config.smtp_timeout_seconds,
                )
                client.starttls(context=context)
            client.login(username, password)
            return client
        except ssl.SSLError as exc:
            raise SmtpTlsError("SMTP TLS verification failed") from exc
        except (smtplib.SMTPException, OSError, socket.timeout) as exc:
            raise SmtpConnectionError("Unable to establish SMTP connection") from exc
