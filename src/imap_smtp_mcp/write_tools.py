from __future__ import annotations

from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, NotFoundError, PermissionDisabledError
from .imap_adapter import ImapAdapter, ImapAdapterError


class WriteMailboxService:
    def __init__(self, imap_adapter: ImapAdapter, config: AppConfig) -> None:
        self._imap_adapter = imap_adapter
        self._config = config

    def _enforce_action(self, action: str) -> None:
        try:
            ensure_action_enabled(action, self._config)
        except CapabilityError as exc:
            raise PermissionDisabledError(str(exc)) from exc

    @staticmethod
    def _validate_single_line(name: str, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise InvalidInputError(f"{name} must be single-line")
        out = value.strip()
        if not out:
            raise InvalidInputError(f"{name} must not be empty")
        return out

    def _select_folder(self, client, folder: str) -> None:
        status, _ = client.select(folder)
        if status != "OK":
            raise NotFoundError(f"Folder not found: {folder}")

    def _ensure_uid_exists(self, client, uid: str) -> None:
        status, data = client.uid("fetch", uid, "(UID)")
        if status != "OK" or not data or data[0] is None:
            raise NotFoundError(f"Email not found: {uid}")

    def _ensure_folder_exists(self, client, folder: str) -> None:
        if folder not in self._imap_adapter.list_folders(client):
            raise NotFoundError(f"Folder not found: {folder}")

    def _ensure_folder_absent(self, client, folder: str) -> None:
        if folder in self._imap_adapter.list_folders(client):
            raise InvalidInputError(f"Folder already exists: {folder}")

    def create_folder(self, username: str, password: str, folder: str) -> None:
        self._enforce_action("create_folder")
        folder_name = self._validate_single_line("folder", folder)
        try:
            client = self._imap_adapter.connect(username, password)
            status, _ = client.create(folder_name)
            if status != "OK":
                raise BackendUnavailableError("Failed to create folder")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def rename_folder(self, username: str, password: str, source_folder: str, target_folder: str) -> None:
        self._enforce_action("rename_folder")
        src = self._validate_single_line("source_folder", source_folder)
        dst = self._validate_single_line("target_folder", target_folder)
        try:
            client = self._imap_adapter.connect(username, password)
            self._ensure_folder_exists(client, src)
            self._ensure_folder_absent(client, dst)
            status, _ = client.rename(src, dst)
            if status != "OK":
                raise BackendUnavailableError("Failed to rename folder")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def delete_folder(self, username: str, password: str, folder: str) -> None:
        self._enforce_action("delete_folder")
        folder_name = self._validate_single_line("folder", folder)
        try:
            client = self._imap_adapter.connect(username, password)
            self._ensure_folder_exists(client, folder_name)
            status, _ = client.delete(folder_name)
            if status != "OK":
                raise BackendUnavailableError("Failed to delete folder")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def mark_read_state(self, username: str, password: str, folder: str, uid: str, is_read: bool) -> None:
        self._enforce_action("mark_read_state")
        folder_name = self._validate_single_line("folder", folder)
        uid_value = self._validate_single_line("uid", uid)
        flag_op = "+FLAGS" if is_read else "-FLAGS"
        try:
            client = self._imap_adapter.connect(username, password)
            self._select_folder(client, folder_name)
            self._ensure_uid_exists(client, uid_value)
            status, _ = client.uid("store", uid_value, flag_op, "(\\Seen)")
            if status != "OK":
                raise NotFoundError(f"Email not found: {uid_value}")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def move_email(self, username: str, password: str, source_folder: str, target_folder: str, uid: str) -> None:
        self._enforce_action("move_email")
        self._copy_or_move(username, password, source_folder, target_folder, uid, is_move=True)

    def copy_email(self, username: str, password: str, source_folder: str, target_folder: str, uid: str) -> None:
        self._enforce_action("copy_email")
        self._copy_or_move(username, password, source_folder, target_folder, uid, is_move=False)

    def _copy_or_move(self, username: str, password: str, source_folder: str, target_folder: str, uid: str, *, is_move: bool) -> None:
        src = self._validate_single_line("source_folder", source_folder)
        dst = self._validate_single_line("target_folder", target_folder)
        uid_value = self._validate_single_line("uid", uid)
        try:
            client = self._imap_adapter.connect(username, password)
            self._select_folder(client, src)
            self._ensure_uid_exists(client, uid_value)
            self._ensure_folder_exists(client, dst)
            status, _ = client.uid("copy", uid_value, dst)
            if status != "OK":
                raise BackendUnavailableError("Failed to copy email")
            if is_move:
                delete_status, _ = client.uid("store", uid_value, "+FLAGS", "(\\Deleted)")
                if delete_status != "OK":
                    raise BackendUnavailableError("Failed to mark email deleted after copy")
                expunge_status, _ = client.expunge()
                if expunge_status != "OK":
                    raise BackendUnavailableError("Failed to expunge moved email")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def delete_email_permanent(self, username: str, password: str, folder: str, uid: str) -> None:
        self._enforce_action("delete_email_permanent")
        folder_name = self._validate_single_line("folder", folder)
        uid_value = self._validate_single_line("uid", uid)
        try:
            client = self._imap_adapter.connect(username, password)
            self._select_folder(client, folder_name)
            self._ensure_uid_exists(client, uid_value)
            status, _ = client.uid("store", uid_value, "+FLAGS", "(\\Deleted)")
            if status != "OK":
                raise NotFoundError(f"Email not found: {uid_value}")
            expunge_status, _ = client.expunge()
            if expunge_status != "OK":
                raise BackendUnavailableError("Failed to expunge deleted email")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc

    def move_to_trash(self, username: str, password: str, source_folder: str, uid: str) -> None:
        self._enforce_action("move_to_trash")
        self._copy_or_move(username, password, source_folder, self._config.trash_folder, uid, is_move=True)

    def empty_trash(self, username: str, password: str) -> None:
        self._enforce_action("empty_trash")
        try:
            client = self._imap_adapter.connect(username, password)
            self._select_folder(client, self._config.trash_folder)
            status, data = client.uid("search", None, "ALL")
            if status != "OK":
                raise BackendUnavailableError("Failed to list trash emails")
            ids = data[0].decode("utf-8").split() if data and data[0] else []
            if ids:
                mark_status, _ = client.uid("store", ",".join(ids), "+FLAGS", "(\\Deleted)")
                if mark_status != "OK":
                    raise BackendUnavailableError("Failed to mark trash emails deleted")
            expunge_status, _ = client.expunge()
            if expunge_status != "OK":
                raise BackendUnavailableError("Failed to expunge trash")
        except ImapAdapterError as exc:
            raise BackendUnavailableError("IMAP backend unavailable") from exc
