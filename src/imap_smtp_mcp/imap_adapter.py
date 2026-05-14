from __future__ import annotations

import imaplib
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Protocol

from .config import AppConfig, ProtocolMode


class ImapAdapterError(RuntimeError):
    """Base error for IMAP adapter failures."""


class ImapTlsError(ImapAdapterError):
    """Raised when TLS or certificate validation fails."""


class ImapConnectionError(ImapAdapterError):
    """Raised when IMAP connection attempts are exhausted."""


class FolderResolutionError(ImapAdapterError):
    """Raised when configured folders cannot be resolved."""


class ImapClient(Protocol):
    def login(self, user: str, password: str) -> tuple[str, list[bytes]]: ...

    def starttls(self, ssl_context: ssl.SSLContext) -> tuple[str, list[bytes]]: ...

    def list(self) -> tuple[str, list[bytes]]: ...

    def logout(self) -> tuple[str, list[bytes]]: ...


ImapFactory = Callable[..., ImapClient]
StartTlsFactory = Callable[[str, int], ImapClient]


@dataclass(frozen=True)
class ResolvedFolders:
    folders: tuple[str, ...]
    sent_folder: str
    trash_folder: str


class ImapAdapter:
    def __init__(
        self,
        config: AppConfig,
        ssl_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        imap_ssl_factory: ImapFactory = imaplib.IMAP4_SSL,
        imap_starttls_factory: StartTlsFactory = imaplib.IMAP4,
    ) -> None:
        self._config = config
        self._ssl_factory = ssl_factory
        self._imap_ssl_factory = imap_ssl_factory
        self._imap_starttls_factory = imap_starttls_factory

    def create_ssl_context(self) -> ssl.SSLContext:
        context = self._ssl_factory()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if self._config.imap_tls_ca_bundle_path:
            context.load_verify_locations(cafile=self._config.imap_tls_ca_bundle_path)
        return context

    def connect(self, username: str, password: str) -> ImapClient:
        retries = self._config.imap_max_retries
        context = self.create_ssl_context()
        last_error: Exception | None = None
        for _ in range(retries + 1):
            try:
                if self._config.imap.mode == ProtocolMode.SSL:
                    client = self._imap_ssl_factory(self._config.imap.host, self._config.imap.port, ssl_context=context)
                else:
                    client = self._imap_starttls_factory(self._config.imap.host, self._config.imap.port)
                    client.starttls(context)
                client.login(username, password)
                return client
            except ssl.SSLError as exc:
                raise ImapTlsError("IMAP TLS verification failed") from exc
            except (imaplib.IMAP4.error, OSError, socket.timeout) as exc:
                last_error = exc
                continue

        raise ImapConnectionError("Unable to establish IMAP connection after retries") from last_error

    def list_folders(self, client: ImapClient) -> tuple[str, ...]:
        status, folders_raw = client.list()
        if status != "OK":
            raise ImapAdapterError("Failed to list IMAP folders")
        parsed: list[str] = []
        for item in folders_raw:
            decoded = item.decode("utf-8", errors="replace")
            parsed.append(_parse_list_folder_name(decoded))
        return tuple(parsed)

    def resolve_configured_folders(self, client: ImapClient) -> ResolvedFolders:
        folders = self.list_folders(client)
        missing = [
            name
            for name in (self._config.sent_folder, self._config.trash_folder)
            if name not in folders
        ]
        if missing:
            raise FolderResolutionError(f"Configured folders missing on IMAP server: {', '.join(missing)}")
        return ResolvedFolders(
            folders=folders,
            sent_folder=self._config.sent_folder,
            trash_folder=self._config.trash_folder,
        )


def _parse_list_folder_name(decoded: str) -> str:
    value = decoded.strip()
    if value.endswith('"'):
        start = value.rfind(' "')
        if start >= 0:
            return value[start + 2 : -1]
    return value.rsplit(" ", 1)[-1].strip('"')
