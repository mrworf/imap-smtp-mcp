from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, cast

from .audit import AuditEvent, AuditLogger
from .capabilities import CapabilityError, ensure_action_enabled
from .config import AppConfig
from .errors import AuthSessionError, BackendUnavailableError, InvalidInputError, MCPError, PermissionDisabledError
from .imap_adapter import ImapAdapter
from .oauth import MailCredentials
from .read_tools import ReadOnlyMailboxService
from .send_tools import SendEmailService
from .smtp_adapter import SmtpAdapter
from .write_tools import WriteMailboxService


READ_SCOPE = "mail:read"
SEND_SCOPE = "mail:send"
WRITE_SCOPE = "mail:write"

TOOL_SCOPES = {
    "list_folders": (READ_SCOPE,),
    "search_emails": (READ_SCOPE,),
    "list_emails": (READ_SCOPE,),
    "read_email": (READ_SCOPE,),
    "send_email": (SEND_SCOPE,),
    "mark_read_state": (WRITE_SCOPE,),
    "move_email": (WRITE_SCOPE,),
    "copy_email": (WRITE_SCOPE,),
    "delete_email_permanent": (WRITE_SCOPE,),
    "move_to_trash": (WRITE_SCOPE,),
    "empty_trash": (WRITE_SCOPE,),
    "create_folder": (WRITE_SCOPE,),
    "rename_folder": (WRITE_SCOPE,),
    "delete_folder": (WRITE_SCOPE,),
}


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_folders": {"type": "object", "properties": {}, "additionalProperties": False},
    "search_emails": {
        "type": "object",
        "required": ["folder", "query"],
        "properties": {"folder": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "default": 50}},
    },
    "list_emails": {
        "type": "object",
        "required": ["folder"],
        "properties": {"folder": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 20}},
    },
    "read_email": {
        "type": "object",
        "required": ["folder", "uid"],
        "properties": {"folder": {"type": "string"}, "uid": {"type": "string"}, "max_chars": {"type": "integer", "default": 20000}},
    },
    "send_email": {
        "type": "object",
        "required": ["to_addresses", "subject", "body_text"],
        "properties": {
            "to_addresses": {"type": "array", "items": {"type": "string"}},
            "subject": {"type": "string"},
            "body_text": {"type": "string"},
            "append_to_sent": {"type": "boolean", "default": True},
        },
    },
    "mark_read_state": {
        "type": "object",
        "required": ["folder", "uid", "is_read"],
        "properties": {"folder": {"type": "string"}, "uid": {"type": "string"}, "is_read": {"type": "boolean"}},
    },
    "move_email": {
        "type": "object",
        "required": ["source_folder", "target_folder", "uid"],
        "properties": {"source_folder": {"type": "string"}, "target_folder": {"type": "string"}, "uid": {"type": "string"}},
    },
    "copy_email": {
        "type": "object",
        "required": ["source_folder", "target_folder", "uid"],
        "properties": {"source_folder": {"type": "string"}, "target_folder": {"type": "string"}, "uid": {"type": "string"}},
    },
    "delete_email_permanent": {
        "type": "object",
        "required": ["folder", "uid"],
        "properties": {"folder": {"type": "string"}, "uid": {"type": "string"}},
    },
    "move_to_trash": {
        "type": "object",
        "required": ["source_folder", "uid"],
        "properties": {"source_folder": {"type": "string"}, "uid": {"type": "string"}},
    },
    "empty_trash": {"type": "object", "properties": {}, "additionalProperties": False},
    "create_folder": {
        "type": "object",
        "required": ["folder"],
        "properties": {"folder": {"type": "string"}},
    },
    "rename_folder": {
        "type": "object",
        "required": ["source_folder", "target_folder"],
        "properties": {"source_folder": {"type": "string"}, "target_folder": {"type": "string"}},
    },
    "delete_folder": {
        "type": "object",
        "required": ["folder"],
        "properties": {"folder": {"type": "string"}},
    },
}


def _jsonify(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _jsonify(item) for key, item in asdict(cast(Any, value)).items()}
    if isinstance(value, tuple):
        return [_jsonify(item) for item in value]
    if isinstance(value, list):
        return [_jsonify(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonify(item) for key, item in value.items()}
    return value


class MailToolController:
    def __init__(
        self,
        config: AppConfig,
        *,
        imap_adapter: ImapAdapter | None = None,
        smtp_adapter: SmtpAdapter | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.config = config
        self.imap_adapter = imap_adapter or ImapAdapter(config)
        self.smtp_adapter = smtp_adapter or SmtpAdapter(config)
        self.audit_logger = audit_logger or AuditLogger(config.audit_log_dir)
        self.read_service = ReadOnlyMailboxService(self.imap_adapter, config)
        self.send_service = SendEmailService(self.smtp_adapter, self.imap_adapter, config)
        self.write_service = WriteMailboxService(self.imap_adapter, config)

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        for name, schema in TOOL_SCHEMAS.items():
            tools.append(
                {
                    "name": name,
                    "description": _description_for(name),
                    "inputSchema": schema,
                    "annotations": _annotations_for(name),
                }
            )
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any], credentials: MailCredentials, *, request_id: str, subject: str) -> Any:
        if name not in TOOL_SCHEMAS:
            raise InvalidInputError(f"Unknown tool: {name}")
        try:
            result = self._dispatch(name, arguments, credentials, request_id=request_id, subject=subject)
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=True))
            return _jsonify(result)
        except MCPError as exc:
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=False, failure_class=exc.code))
            raise
        except Exception as exc:
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=False, failure_class="backend_unavailable"))
            raise BackendUnavailableError("Unexpected tool failure") from exc

    def _dispatch(self, name: str, args: dict[str, Any], c: MailCredentials, *, request_id: str, subject: str) -> Any:
        if name == "list_folders":
            return self.read_service.list_folders(c.imap_username, c.imap_password)
        if name == "search_emails":
            return {"uids": self.read_service.search_emails(c.imap_username, c.imap_password, str(args["folder"]), str(args["query"]), int(args.get("limit", 50)))}
        if name == "list_emails":
            return self.read_service.list_emails(c.imap_username, c.imap_password, str(args["folder"]), int(args.get("offset", 0)), int(args.get("limit", 20)))
        if name == "read_email":
            result = self.read_service.read_email(c.imap_username, c.imap_password, str(args["folder"]), str(args["uid"]), int(args.get("max_chars", 20000)))
            out = _jsonify(result)
            out["truncated"] = len(result.body_text) >= int(args.get("max_chars", 20000))
            return out
        if name == "send_email":
            try:
                ensure_action_enabled("send_email", self.config)
            except CapabilityError as exc:
                raise PermissionDisabledError(str(exc)) from exc
            if not c.sender_email:
                raise AuthSessionError("Sender identity is missing; reauthorize before sending email")
            reply_to_override = "reply_to" in args
            self._audit_sender_override(args, c, request_id=request_id, subject=subject)
            self.send_service.send_email(
                c.smtp_username,
                c.smtp_password,
                c.imap_username,
                c.imap_password,
                c.sender_email,
                tuple(str(v) for v in args["to_addresses"]),
                str(args["subject"]),
                str(args["body_text"]),
                from_display_name=c.sender_display_name,
                reply_to_address=c.sender_email if reply_to_override else None,
                append_to_sent=bool(args.get("append_to_sent", True)),
            )
            return {"sent": True}
        if name == "mark_read_state":
            self.write_service.mark_read_state(c.imap_username, c.imap_password, str(args["folder"]), str(args["uid"]), bool(args["is_read"]))
            return {"updated": True}
        if name == "move_email":
            self.write_service.move_email(c.imap_username, c.imap_password, str(args["source_folder"]), str(args["target_folder"]), str(args["uid"]))
            return {"moved": True}
        if name == "copy_email":
            self.write_service.copy_email(c.imap_username, c.imap_password, str(args["source_folder"]), str(args["target_folder"]), str(args["uid"]))
            return {"copied": True}
        if name == "delete_email_permanent":
            self.write_service.delete_email_permanent(c.imap_username, c.imap_password, str(args["folder"]), str(args["uid"]))
            return {"deleted": True}
        if name == "move_to_trash":
            self.write_service.move_to_trash(c.imap_username, c.imap_password, str(args["source_folder"]), str(args["uid"]))
            return {"trashed": True}
        if name == "empty_trash":
            self.write_service.empty_trash(c.imap_username, c.imap_password)
            return {"emptied": True}
        if name == "create_folder":
            self.write_service.create_folder(c.imap_username, c.imap_password, str(args["folder"]))
            return {"created": True}
        if name == "rename_folder":
            self.write_service.rename_folder(c.imap_username, c.imap_password, str(args["source_folder"]), str(args["target_folder"]))
            return {"renamed": True}
        if name == "delete_folder":
            self.write_service.delete_folder(c.imap_username, c.imap_password, str(args["folder"]))
            return {"deleted": True}
        raise InvalidInputError(f"Unknown tool: {name}")

    def _audit_sender_override(self, args: dict[str, Any], credentials: MailCredentials, *, request_id: str, subject: str) -> None:
        requested_keys = {"from_address", "from_display_name", "reply_to"}
        if not requested_keys.intersection(args):
            return
        metadata = {
            "requested_from_address": _safe_optional(args.get("from_address")),
            "requested_from_display_name": _safe_optional(args.get("from_display_name")),
            "requested_reply_to": _safe_optional(args.get("reply_to")),
            "actual_sender_email": credentials.sender_email,
            "actual_sender_display_name": credentials.sender_display_name,
        }
        self.audit_logger.log_tool_invocation(
            AuditEvent(
                request_id=request_id,
                mcp_user=subject,
                operation="sender_identity_override",
                success=True,
                metadata=metadata,
            )
        )


def _safe_optional(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _description_for(name: str) -> str:
    descriptions = {
        "list_folders": "List mailbox folders for the authenticated mail account.",
        "search_emails": "Search emails in a folder and return matching IMAP UIDs.",
        "list_emails": "List email summaries in a folder with pagination.",
        "read_email": "Read one email by IMAP UID with bounded body text.",
        "send_email": "Send an email using the authenticated SMTP credentials.",
        "mark_read_state": "Mark an email read or unread.",
        "move_email": "Move an email from one folder to another.",
        "copy_email": "Copy an email from one folder to another.",
        "delete_email_permanent": "Permanently delete an email and expunge it.",
        "move_to_trash": "Move an email to the configured trash folder.",
        "empty_trash": "Permanently delete all mail in the configured trash folder.",
        "create_folder": "Create an IMAP folder.",
        "rename_folder": "Rename an IMAP folder.",
        "delete_folder": "Delete an IMAP folder using the server's default IMAP DELETE behavior.",
    }
    return descriptions[name]


def _annotations_for(name: str) -> dict[str, Any]:
    if name in {"send_email", "mark_read_state", "move_email", "copy_email", "delete_email_permanent", "move_to_trash", "empty_trash", "create_folder", "rename_folder", "delete_folder"}:
        return {"readOnlyHint": False, "destructiveHint": name in {"delete_email_permanent", "empty_trash", "delete_folder"}}
    return {"readOnlyHint": True, "destructiveHint": False}
