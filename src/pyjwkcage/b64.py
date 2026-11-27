"""Canonical base64url helpers for JWK and JOSE header parameters."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from .errors import BASE64URL_INVALID, JwkCageError

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(
    value: object,
    field: str,
    *,
    max_bytes: int = 8192,
    allow_empty: bool = False,
) -> bytes:
    if not isinstance(value, str):
        raise JwkCageError(BASE64URL_INVALID, "base64url value must be a string", field)
    if not value:
        if allow_empty:
            return b""
        raise JwkCageError(BASE64URL_INVALID, "base64url value must not be empty", field)
    if len(value) > ((max_bytes + 2) // 3) * 4:
        raise JwkCageError(BASE64URL_INVALID, "base64url value is too large", field)
    if "=" in value or not _B64URL_RE.match(value):
        raise JwkCageError(BASE64URL_INVALID, "base64url value is padded or contains forbidden characters", field)
    if len(value) % 4 == 1:
        raise JwkCageError(BASE64URL_INVALID, "base64url value has an impossible length", field)
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise JwkCageError(BASE64URL_INVALID, "base64url value cannot be decoded", field) from exc
    if len(decoded) > max_bytes:
        raise JwkCageError(BASE64URL_INVALID, "decoded base64url value is too large", field)
    if b64url_encode(decoded) != value:
        raise JwkCageError(BASE64URL_INVALID, "base64url value is not canonical", field)
    return decoded


def b64url_uint(value: object, field: str, *, max_bytes: int = 8192) -> int:
    decoded = b64url_decode(value, field, max_bytes=max_bytes)
    if len(decoded) > 1 and decoded[0] == 0:
        raise JwkCageError(BASE64URL_INVALID, "unsigned integer base64url value has a leading zero octet", field)
    return int.from_bytes(decoded, "big")


def b64url_uint_bytes(value: object, field: str, *, max_bytes: int = 8192) -> bytes:
    decoded = b64url_decode(value, field, max_bytes=max_bytes)
    if len(decoded) > 1 and decoded[0] == 0:
        raise JwkCageError(BASE64URL_INVALID, "unsigned integer base64url value has a leading zero octet", field)
    return decoded


def optional_b64url(obj: dict, field: str, *, max_bytes: int = 8192) -> Optional[bytes]:
    if field not in obj:
        return None
    return b64url_decode(obj[field], field, max_bytes=max_bytes, allow_empty=True)


__all__ = ["b64url_decode", "b64url_encode", "b64url_uint", "b64url_uint_bytes", "optional_b64url"]
