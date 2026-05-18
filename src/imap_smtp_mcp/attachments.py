from __future__ import annotations

import base64
import binascii
import mimetypes
import re
from dataclasses import dataclass
from pathlib import PurePath

from .errors import InvalidInputError


DEFAULT_BLOCKED_MIME_TYPES = (
    "application/javascript",
    "application/ecmascript",
    "text/html",
    "text/javascript",
    "text/ecmascript",
)
DEFAULT_BLOCKED_EXTENSIONS = (".htm", ".html", ".js", ".mjs")
MAX_COMPUTED_JSON_BODY_BYTES = 100 * 1024 * 1024
JSON_BODY_BASE_BYTES = 1_048_576
JSON_ATTACHMENT_OVERHEAD_BYTES = 4096
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class AttachmentPolicy:
    max_count: int = 10
    max_bytes: int = 1_048_576
    blocked_mime_types: tuple[str, ...] = DEFAULT_BLOCKED_MIME_TYPES
    blocked_extensions: tuple[str, ...] = DEFAULT_BLOCKED_EXTENSIONS


@dataclass(frozen=True)
class AttachmentData:
    filename: str
    content_type: str
    content: bytes


def normalize_content_type(value: str) -> str:
    content_type = value.split(";", 1)[0].strip().lower()
    if not content_type or "/" not in content_type:
        raise InvalidInputError("attachment content_type is invalid")
    if _CONTROL_RE.search(content_type) or any(ch.isspace() for ch in content_type):
        raise InvalidInputError("attachment content_type is invalid")
    return content_type


def normalize_extension(filename: str) -> str:
    suffix = PurePath(filename).suffix
    return suffix.lower()


def validate_attachment_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise InvalidInputError("attachment filename must be a string")
    normalized = filename.strip()
    if not normalized:
        raise InvalidInputError("attachment filename must not be empty")
    if "/" in normalized or "\\" in normalized:
        raise InvalidInputError("attachment filename must not contain path separators")
    if _CONTROL_RE.search(normalized):
        raise InvalidInputError("attachment filename must not contain control characters")
    if normalized in {".", ".."}:
        raise InvalidInputError("attachment filename is invalid")
    return normalized


def policy_block_reason(filename: str, content_type: str, policy: AttachmentPolicy) -> str | None:
    normalized_type = normalize_content_type(content_type)
    if normalized_type in policy.blocked_mime_types:
        return "blocked_mime_type"
    extension = normalize_extension(filename)
    if extension and extension in policy.blocked_extensions:
        return "blocked_extension"
    return None


def validate_attachment_allowed(filename: str, content_type: str, size_bytes: int, policy: AttachmentPolicy) -> None:
    safe_filename = validate_attachment_filename(filename)
    normalized_type = normalize_content_type(content_type)
    reason = policy_block_reason(safe_filename, normalized_type, policy)
    if reason == "blocked_mime_type":
        raise InvalidInputError(f"attachment blocked by MIME type: {normalized_type}")
    if reason == "blocked_extension":
        raise InvalidInputError(f"attachment blocked by extension: {normalize_extension(safe_filename)}")
    if size_bytes > policy.max_bytes:
        raise InvalidInputError(f"attachment exceeds maximum size of {policy.max_bytes} bytes")


def decode_attachment_base64(value: object) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise InvalidInputError("attachment content_base64 must be a non-empty base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInputError("attachment content_base64 is invalid base64") from exc


def encode_attachment_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def infer_content_type(filename: str, fallback: str = "application/octet-stream") -> str:
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or fallback


def compute_json_body_limit(policy: AttachmentPolicy) -> int:
    encoded_per_attachment = ((policy.max_bytes + 2) // 3) * 4
    total = JSON_BODY_BASE_BYTES + policy.max_count * (encoded_per_attachment + JSON_ATTACHMENT_OVERHEAD_BYTES)
    if total > MAX_COMPUTED_JSON_BODY_BYTES:
        raise ValueError(f"computed MCP JSON body limit exceeds {MAX_COMPUTED_JSON_BODY_BYTES} bytes")
    return total
