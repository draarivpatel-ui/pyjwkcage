"""Strict JSON object parsing used before any security decision."""
from __future__ import annotations

import json
import unicodedata
from typing import Any, Dict, Mapping, Tuple

from .errors import JSON_DUPLICATE_KEY, JSON_INVALID, JwkCageError

DEFAULT_MAX_JSON_SIZE = 16384
DEFAULT_MAX_DEPTH = 24
DEFAULT_MAX_NODES = 512
DEFAULT_MAX_STRING = 4096


def _duplicate_rejecting_object(pairs: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JwkCageError(JSON_DUPLICATE_KEY, "duplicate JSON member name", key)
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise JwkCageError(JSON_INVALID, "non-finite JSON numbers are forbidden")


def deep_copy_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): deep_copy_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [deep_copy_json(item) for item in value]
    if isinstance(value, tuple):
        return [deep_copy_json(item) for item in value]
    return value


def validate_json_tree(
    value: Any,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_string: int = DEFAULT_MAX_STRING,
) -> None:
    nodes = [0]

    def walk(item: Any, depth: int) -> None:
        nodes[0] += 1
        if nodes[0] > max_nodes:
            raise JwkCageError(JSON_INVALID, "JSON document has too many values")
        if depth > max_depth:
            raise JwkCageError(JSON_INVALID, "JSON document is nested too deeply")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise JwkCageError(JSON_INVALID, "JSON object member names must be strings")
                validate_json_string(key, max_string=max_string, what="member name")
                walk(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            validate_json_string(item, max_string=max_string, what="string value")
        elif isinstance(item, bool) or item is None:
            return
        elif isinstance(item, int):
            if abs(item) > (1 << 63):
                raise JwkCageError(JSON_INVALID, "JSON integer is outside the signed 64 bit range")
        elif isinstance(item, float):
            if item != item or item in (float("inf"), float("-inf")):
                raise JwkCageError(JSON_INVALID, "non-finite JSON numbers are forbidden")
        else:
            raise JwkCageError(JSON_INVALID, "JSON values must be objects, arrays, strings, numbers, booleans or null")

    walk(value, 0)


def validate_json_string(value: str, *, max_string: int, what: str) -> None:
    if len(value) > max_string:
        raise JwkCageError(JSON_INVALID, what + " is too long")
    for char in value:
        codepoint = ord(char)
        category = unicodedata.category(char)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or category in ("Cs", "Cn"):
            raise JwkCageError(JSON_INVALID, what + " contains forbidden control or surrogate characters")


def parse_json_object(
    data: Any,
    *,
    max_size: int = DEFAULT_MAX_JSON_SIZE,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> Dict[str, Any]:
    """Parse ``data`` into a strict JSON object.

    Mappings are accepted as already-decoded input. Text and bytes are decoded
    as UTF-8 JSON with duplicate member rejection. The result is a deep copy,
    so later mutation of the input cannot alter a security decision.
    """
    if isinstance(data, Mapping):
        result = deep_copy_json(dict(data))
    elif isinstance(data, (str, bytes, bytearray)):
        if isinstance(data, str):
            try:
                encoded = data.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise JwkCageError(JSON_INVALID, "JSON text contains unpaired surrogate characters") from exc
        else:
            encoded = bytes(data)
        if len(encoded) > max_size:
            raise JwkCageError(JSON_INVALID, "JSON document is too large")
        try:
            text = encoded.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise JwkCageError(JSON_INVALID, "JSON document is not valid UTF-8") from exc
        if text.startswith("\ufeff"):
            raise JwkCageError(JSON_INVALID, "JSON document must not start with a byte order mark")
        try:
            result = json.loads(
                text,
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=_reject_constant,
            )
        except JwkCageError:
            raise
        except (ValueError, TypeError) as exc:
            raise JwkCageError(JSON_INVALID, "JSON document is malformed") from exc
    else:
        raise JwkCageError(JSON_INVALID, "expected a JSON object, object text, bytes or mapping")
    if not isinstance(result, dict):
        raise JwkCageError(JSON_INVALID, "JSON document must be an object")
    validate_json_tree(result, max_depth=max_depth, max_nodes=max_nodes)
    return result


def compact_json(value: Mapping[str, Any]) -> str:
    """Serialize canonical JSON for RFC 7638."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


__all__ = ["compact_json", "deep_copy_json", "parse_json_object", "validate_json_tree"]
