import pytest

from imap_smtp_mcp.attachments import (
    AttachmentPolicy,
    decode_attachment_base64,
    normalize_content_type,
    policy_block_reason,
    validate_attachment_allowed,
    validate_attachment_filename,
)
from imap_smtp_mcp.errors import InvalidInputError


def test_attachment_policy_blocks_mime_and_extension_case_insensitively() -> None:
    policy = AttachmentPolicy(
        max_count=10,
        max_bytes=1024,
        blocked_mime_types=("text/html",),
        blocked_extensions=(".js",),
    )

    assert policy_block_reason("report.txt", "Text/HTML; charset=utf-8", policy) == "blocked_mime_type"
    assert policy_block_reason("SCRIPT.JS", "text/plain", policy) == "blocked_extension"
    assert policy_block_reason("report.txt", "text/plain", policy) is None


def test_attachment_validation_accepts_safe_metadata() -> None:
    policy = AttachmentPolicy(max_count=10, max_bytes=8, blocked_mime_types=(), blocked_extensions=())

    validate_attachment_allowed("report.txt", "text/plain", 8, policy)


@pytest.mark.parametrize("filename", ["", "../secret.txt", "dir/file.txt", "dir\\file.txt", "bad\nname.txt", "\x00.txt"])
def test_attachment_filename_rejects_unsafe_values(filename: str) -> None:
    with pytest.raises(InvalidInputError, match="attachment filename"):
        validate_attachment_filename(filename)


@pytest.mark.parametrize("content_type", ["", "text plain", "text/plain\nbad", "plain"])
def test_attachment_content_type_rejects_invalid_values(content_type: str) -> None:
    with pytest.raises(InvalidInputError, match="attachment content_type is invalid"):
        normalize_content_type(content_type)


def test_attachment_validation_rejects_oversized_content() -> None:
    policy = AttachmentPolicy(max_count=10, max_bytes=3, blocked_mime_types=(), blocked_extensions=())

    with pytest.raises(InvalidInputError, match="attachment exceeds maximum size"):
        validate_attachment_allowed("report.txt", "text/plain", 4, policy)


def test_attachment_base64_decoder_accepts_and_rejects_strictly() -> None:
    assert decode_attachment_base64("aGVsbG8=") == b"hello"

    with pytest.raises(InvalidInputError, match="invalid base64"):
        decode_attachment_base64("not base64")
