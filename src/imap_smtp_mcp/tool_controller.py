from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, cast

from .audit import AuditEvent, AuditLogger
from .config import AppConfig
from .errors import BackendUnavailableError, InvalidInputError, MCPError
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
        "required": ["from_address", "to_addresses", "subject", "body_text"],
        "properties": {
            "from_address": {"type": "string"},
            "to_addresses": {"type": "array", "items": {"type": "string"}},
            "subject": {"type": "string"},
            "body_text": {"type": "string"},
            "from_display_name": {"type": "string"},
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
            result = self._dispatch(name, arguments, credentials)
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=True))
            return _jsonify(result)
        except MCPError as exc:
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=False, failure_class=exc.code))
            raise
        except Exception as exc:
            self.audit_logger.log_tool_invocation(AuditEvent(request_id=request_id, mcp_user=subject, operation=name, success=False, failure_class="backend_unavailable"))
            raise BackendUnavailableError("Unexpected tool failure") from exc

    def _dispatch(self, name: str, args: dict[str, Any], c: MailCredentials) -> Any:
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
            self.send_service.send_email(
                c.smtp_username,
                c.smtp_password,
                c.imap_username,
                c.imap_password,
                str(args["from_address"]),
                tuple(str(v) for v in args["to_addresses"]),
                str(args["subject"]),
                str(args["body_text"]),
                from_display_name=args.get("from_display_name"),
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
        raise InvalidInputError(f"Unknown tool: {name}")


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
    }
    return descriptions[name]


def _annotations_for(name: str) -> dict[str, Any]:
    if name in {"send_email", "mark_read_state", "move_email", "copy_email", "delete_email_permanent", "move_to_trash", "empty_trash"}:
        return {"readOnlyHint": False, "destructiveHint": name in {"delete_email_permanent", "empty_trash"}}
    return {"readOnlyHint": True, "destructiveHint": False}
