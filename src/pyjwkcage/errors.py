"""Stable error codes and exceptions for pyjwkcage."""
from __future__ import annotations

from typing import Optional, Tuple

ALG_CONFUSION = "ALG_CONFUSION"
ALG_NONE = "ALG_NONE"
ALG_NOT_ALLOWED = "ALG_NOT_ALLOWED"
ALG_UNSUPPORTED = "ALG_UNSUPPORTED"
BASE64URL_INVALID = "BASE64URL_INVALID"
CONFIG_INVALID = "CONFIG_INVALID"
CRIT_INVALID = "CRIT_INVALID"
CRIT_UNSUPPORTED = "CRIT_UNSUPPORTED"
CURVE_UNSUPPORTED = "CURVE_UNSUPPORTED"
HEADER_FORBIDDEN = "HEADER_FORBIDDEN"
HEADER_INVALID = "HEADER_INVALID"
JWK_INVALID = "JWK_INVALID"
JWKS_INVALID = "JWKS_INVALID"
JSON_DUPLICATE_KEY = "JSON_DUPLICATE_KEY"
JSON_INVALID = "JSON_INVALID"
KEY_AMBIGUOUS = "KEY_AMBIGUOUS"
KEY_NOT_FOUND = "KEY_NOT_FOUND"
KEY_OPS_INVALID = "KEY_OPS_INVALID"
KEY_OPS_MISMATCH = "KEY_OPS_MISMATCH"
KEY_PARAMETER_INVALID = "KEY_PARAMETER_INVALID"
KEY_SIZE_WEAK = "KEY_SIZE_WEAK"
KID_COLLISION = "KID_COLLISION"
KID_DUPLICATE = "KID_DUPLICATE"
KID_INVALID = "KID_INVALID"
KID_REQUIRED = "KID_REQUIRED"
KTY_UNSUPPORTED = "KTY_UNSUPPORTED"
PRIVATE_MATERIAL = "PRIVATE_MATERIAL"
REMOTE_KEY_REFERENCE = "REMOTE_KEY_REFERENCE"
REMOTE_URL_UNSAFE = "REMOTE_URL_UNSAFE"
THUMBPRINT_INVALID = "THUMBPRINT_INVALID"
USE_INVALID = "USE_INVALID"
USE_MISMATCH = "USE_MISMATCH"

ERROR_CODES: Tuple[str, ...] = (
    ALG_CONFUSION,
    ALG_NONE,
    ALG_NOT_ALLOWED,
    ALG_UNSUPPORTED,
    BASE64URL_INVALID,
    CONFIG_INVALID,
    CRIT_INVALID,
    CRIT_UNSUPPORTED,
    CURVE_UNSUPPORTED,
    HEADER_FORBIDDEN,
    HEADER_INVALID,
    JWK_INVALID,
    JWKS_INVALID,
    JSON_DUPLICATE_KEY,
    JSON_INVALID,
    KEY_AMBIGUOUS,
    KEY_NOT_FOUND,
    KEY_OPS_INVALID,
    KEY_OPS_MISMATCH,
    KEY_PARAMETER_INVALID,
    KEY_SIZE_WEAK,
    KID_COLLISION,
    KID_DUPLICATE,
    KID_INVALID,
    KID_REQUIRED,
    KTY_UNSUPPORTED,
    PRIVATE_MATERIAL,
    REMOTE_KEY_REFERENCE,
    REMOTE_URL_UNSAFE,
    THUMBPRINT_INVALID,
    USE_INVALID,
    USE_MISMATCH,
)


class JwkCageError(Exception):
    """Exception raised for strict parsing and key selection failures.

    The ``code`` attribute is stable API. Messages deliberately omit key
    material and attacker controlled field values.
    """

    __slots__ = ("code", "message", "field")

    def __init__(self, code: str, message: str, field: Optional[str] = None) -> None:
        self.code = code
        self.message = message
        self.field = field
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.field:
            return "{}: {} ({})".format(self.code, self.message, self.field)
        return "{}: {}".format(self.code, self.message)

    def to_dict(self) -> dict:
        result = {"code": self.code, "message": self.message}
        if self.field:
            result["field"] = self.field
        return result


__all__ = list(ERROR_CODES) + ["ERROR_CODES", "JwkCageError"]
