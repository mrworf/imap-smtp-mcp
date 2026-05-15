from __future__ import annotations

import re

from .errors import InvalidInputError


_SINGLE_UID_RE = re.compile(r"^[1-9][0-9]*$")


def validate_single_message_uid(name: str, value: str) -> str:
    if "\r" in value or "\n" in value:
        raise InvalidInputError(f"{name} must be single-line")
    normalized = value.strip()
    if not normalized:
        raise InvalidInputError(f"{name} must not be empty")
    if not _SINGLE_UID_RE.fullmatch(normalized):
        raise InvalidInputError(f"{name} must be a positive integer UID")
    return normalized
