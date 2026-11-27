"""JWK, JWKS and JOSE header security policy implementation."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .b64 import b64url_decode, b64url_encode, b64url_uint
from .errors import (
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
    JwkCageError,
)
from .jsonutil import compact_json, deep_copy_json, parse_json_object, validate_json_tree
from .model import AuditReport, Finding, make_report
from .netguard import audit_https_url

PRIVATE_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})
RSA_PRIVATE_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})

HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
RSA_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
EC_ALGORITHMS = frozenset({"ES256", "ES384", "ES512"})
OKP_ALGORITHMS = frozenset({"EdDSA"})
SIGNING_ALGORITHMS = HMAC_ALGORITHMS | RSA_ALGORITHMS | EC_ALGORITHMS | OKP_ALGORITHMS

JWE_RSA_ALGORITHMS = frozenset({"RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"})
JWE_EC_ALGORITHMS = frozenset({"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"})
JWE_OCT_ALGORITHMS = frozenset(
    {
        "dir",
        "A128KW",
        "A192KW",
        "A256KW",
        "A128GCMKW",
        "A192GCMKW",
        "A256GCMKW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    }
)
WEAK_JWE_ALGORITHMS = frozenset({"RSA1_5"})
JOSE_ALGORITHMS = SIGNING_ALGORITHMS | JWE_RSA_ALGORITHMS | JWE_EC_ALGORITHMS | JWE_OCT_ALGORITHMS | WEAK_JWE_ALGORITHMS

JWE_ENC_ALGORITHMS = frozenset(
    {
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    }
)

VALID_USES = frozenset({"sig", "enc"})
VALID_KEY_OPS = frozenset(
    {"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"}
)
REGISTERED_CRIT_NAMES = frozenset(
    {"alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"}
)

_KID_RE = re.compile(r"^[A-Za-z0-9_.:@=-]+$")
_X5C_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

CURVES: Dict[str, Dict[str, Any]] = {
    "P-256": {
        "algorithm": "ES256",
        "coordinate_bytes": 32,
        "p": int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
        "b": int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
    },
    "P-384": {
        "algorithm": "ES384",
        "coordinate_bytes": 48,
        "p": int(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
            "ffffffff0000000000000000ffffffff",
            16,
        ),
        "b": int(
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
            "c656398d8a2ed19d2a85c8edd3ec2aef",
            16,
        ),
    },
    "P-521": {
        "algorithm": "ES512",
        "coordinate_bytes": 66,
        "p": (1 << 521) - 1,
        "b": int(
            "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
            "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            16,
        ),
    },
}
OKP_CURVE_SIZES = {"Ed25519": 32, "Ed448": 57}


def _finding(code: str, message: str, field: Optional[str] = None, key_index: Optional[int] = None) -> Finding:
    return Finding(code=code, message=message, field=field, key_index=key_index)


def _error_to_finding(error: JwkCageError, key_index: Optional[int] = None) -> Finding:
    return _finding(error.code, error.message, error.field, key_index)


def _copy_object(data: Any, *, max_size: int, max_nodes: int = 1024) -> Dict[str, Any]:
    return parse_json_object(data, max_size=max_size, max_nodes=max_nodes)


def _validate_kid(value: Any, field: str = "kid") -> Optional[Finding]:
    if not isinstance(value, str):
        return _finding(KID_INVALID, "kid must be a string", field)
    if not value:
        return _finding(KID_INVALID, "kid must not be empty", field)
    if len(value) > 256:
        return _finding(KID_INVALID, "kid is too long", field)
    if ".." in value:
        return _finding(KID_INVALID, "kid must not contain path traversal", field)
    if "--" in value or "/*" in value or "*/" in value:
        return _finding(KID_INVALID, "kid must not contain SQL comment markers", field)
    if not _KID_RE.match(value):
        return _finding(
            KID_INVALID,
            "kid contains characters usable for traversal, SQL injection, CRLF injection or parser confusion",
            field,
        )
    return None


def _key_family_for_algorithm(algorithm: str) -> Optional[str]:
    if algorithm in HMAC_ALGORITHMS or algorithm in JWE_OCT_ALGORITHMS:
        return "oct"
    if algorithm in RSA_ALGORITHMS or algorithm in JWE_RSA_ALGORITHMS or algorithm in WEAK_JWE_ALGORITHMS:
        return "RSA"
    if algorithm in EC_ALGORITHMS or algorithm in JWE_EC_ALGORITHMS:
        return "EC"
    if algorithm in OKP_ALGORITHMS:
        return "OKP"
    return None


def _validate_algorithm_value(value: Any, field: str = "alg") -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(value, str):
        findings.append(_finding(ALG_UNSUPPORTED, "algorithm must be a string", field))
        return findings
    if value.strip().lower() == "none":
        findings.append(_finding(ALG_NONE, "the none algorithm is forbidden", field))
        return findings
    if not value or value != value.strip():
        findings.append(_finding(ALG_UNSUPPORTED, "algorithm must be exact and must not contain outer whitespace", field))
        return findings
    if value in WEAK_JWE_ALGORITHMS:
        findings.append(_finding(ALG_UNSUPPORTED, "obsolete RSA key transport is forbidden", field))
    elif value not in JOSE_ALGORITHMS:
        findings.append(_finding(ALG_UNSUPPORTED, "algorithm is not in the approved RFC 7518 set", field))
    return findings


def _validate_use_and_ops(obj: Mapping[str, Any], expected_use: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    use = obj.get("use")
    if use is not None:
        if not isinstance(use, str) or use not in VALID_USES:
            findings.append(_finding(USE_INVALID, "use must be exactly sig or enc", "use"))
        elif expected_use is not None and use != expected_use:
            findings.append(_finding(USE_MISMATCH, "key use does not match the required operation", "use"))
    key_ops = obj.get("key_ops")
    ops: List[str] = []
    if key_ops is not None:
        if not isinstance(key_ops, list) or not key_ops:
            findings.append(_finding(KEY_OPS_INVALID, "key_ops must be a non-empty array", "key_ops"))
        else:
            seen = set()
            for item in key_ops:
                if not isinstance(item, str) or item not in VALID_KEY_OPS:
                    findings.append(_finding(KEY_OPS_INVALID, "key_ops contains an unknown operation", "key_ops"))
                    continue
                if item in seen:
                    findings.append(_finding(KEY_OPS_INVALID, "key_ops contains a duplicate operation", "key_ops"))
                seen.add(item)
                ops.append(item)
            signature_ops = {"sign", "verify"}
            encryption_ops = {"encrypt", "decrypt", "wrapKey", "unwrapKey"}
            if any(item in signature_ops for item in ops) and any(item in encryption_ops for item in ops):
                findings.append(_finding(KEY_OPS_MISMATCH, "one key must not mix signature and encryption operations", "key_ops"))
            if expected_use == "sig" and "verify" not in ops:
                findings.append(_finding(KEY_OPS_MISMATCH, "verification keys must list the verify key operation", "key_ops"))
            if expected_use == "enc" and not any(item in encryption_ops or item in {"deriveKey", "deriveBits"} for item in ops):
                findings.append(_finding(KEY_OPS_MISMATCH, "encryption keys must list an encryption or key agreement operation", "key_ops"))
    if use == "sig" and key_ops is not None and not any(item in {"sign", "verify"} for item in ops):
        findings.append(_finding(KEY_OPS_MISMATCH, "use sig conflicts with key_ops", "key_ops"))
    if use == "enc" and key_ops is not None and any(item in {"sign", "verify"} for item in ops):
        findings.append(_finding(KEY_OPS_MISMATCH, "use enc conflicts with key_ops", "key_ops"))
    return findings


def _validate_x5c(value: Any) -> Optional[Finding]:
    if not isinstance(value, list) or not value or len(value) > 8:
        return _finding(KEY_PARAMETER_INVALID, "x5c must be a small non-empty certificate chain array", "x5c")
    for item in value:
        if not isinstance(item, str) or len(item) > 8192 or len(item) % 4 != 0 or not _X5C_RE.match(item):
            return _finding(KEY_PARAMETER_INVALID, "x5c entries must be canonical padded base64 strings", "x5c")
    return None


def _point_on_curve(x: int, y: int, curve: Mapping[str, Any]) -> bool:
    p = int(curve["p"])
    if x < 0 or x >= p or y < 0 or y >= p:
        return False
    return (y * y - (x * x * x - 3 * x + int(curve["b"]))) % p == 0


def _validate_rsa(obj: Mapping[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    try:
        n_bytes = b64url_decode(obj.get("n"), "n", max_bytes=2048)
        n = b64url_uint(obj.get("n"), "n", max_bytes=2048)
        e = b64url_uint(obj.get("e"), "e", max_bytes=64)
    except JwkCageError as exc:
        return [_error_to_finding(exc)]
    bit_length = n.bit_length()
    if bit_length < 2048:
        findings.append(_finding(KEY_SIZE_WEAK, "RSA modulus is below 2048 bits", "n"))
    if bit_length > 16384:
        findings.append(_finding(KEY_PARAMETER_INVALID, "RSA modulus is unreasonably large", "n"))
    if n % 2 == 0:
        findings.append(_finding(KEY_PARAMETER_INVALID, "RSA modulus must be odd", "n"))
    if len(n_bytes) * 8 - bit_length > 7:
        findings.append(_finding(KEY_PARAMETER_INVALID, "RSA modulus has noncanonical leading zero bits", "n"))
    if e < 65537:
        findings.append(_finding(KEY_SIZE_WEAK, "RSA public exponent is below 65537", "e"))
    if e % 2 == 0:
        findings.append(_finding(KEY_PARAMETER_INVALID, "RSA public exponent must be odd", "e"))
    if e >= n:
        findings.append(_finding(KEY_PARAMETER_INVALID, "RSA public exponent must be smaller than the modulus", "e"))
    return findings


def _validate_ec(obj: Mapping[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    curve_name = obj.get("crv")
    if not isinstance(curve_name, str) or curve_name not in CURVES:
        return [_finding(CURVE_UNSUPPORTED, "EC curve is unknown or not approved", "crv")]
    curve = CURVES[curve_name]
    size = int(curve["coordinate_bytes"])
    try:
        x_bytes = b64url_decode(obj.get("x"), "x", max_bytes=size)
        y_bytes = b64url_decode(obj.get("y"), "y", max_bytes=size)
    except JwkCageError as exc:
        return [_error_to_finding(exc)]
    if len(x_bytes) != size or len(y_bytes) != size:
        findings.append(_finding(KEY_PARAMETER_INVALID, "EC coordinates must use the exact curve encoding length", "x"))
        return findings
    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")
    if not _point_on_curve(x, y, curve):
        findings.append(_finding(KEY_PARAMETER_INVALID, "EC public point is not on the approved curve", "x"))
    algorithm = obj.get("alg")
    if isinstance(algorithm, str) and algorithm in EC_ALGORITHMS and algorithm != curve["algorithm"]:
        findings.append(_finding(ALG_CONFUSION, "EC key curve does not match its declared algorithm", "alg"))
    return findings


def _validate_okp(obj: Mapping[str, Any]) -> List[Finding]:
    curve_name = obj.get("crv")
    if not isinstance(curve_name, str) or curve_name not in OKP_CURVE_SIZES:
        return [_finding(CURVE_UNSUPPORTED, "OKP curve is unknown or not approved", "crv")]
    try:
        x_bytes = b64url_decode(obj.get("x"), "x", max_bytes=OKP_CURVE_SIZES[curve_name])
    except JwkCageError as exc:
        return [_error_to_finding(exc)]
    if len(x_bytes) != OKP_CURVE_SIZES[curve_name]:
        return [_finding(KEY_PARAMETER_INVALID, "OKP public key has the wrong encoding length", "x")]
    return []


def _validate_oct(obj: Mapping[str, Any]) -> List[Finding]:
    try:
        key = b64url_decode(obj.get("k"), "k", max_bytes=512)
    except JwkCageError as exc:
        return [_error_to_finding(exc)]
    findings: List[Finding] = []
    if len(key) < 32:
        findings.append(_finding(KEY_SIZE_WEAK, "HMAC key material is below 256 bits", "k"))
    algorithm = obj.get("alg")
    required = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm)
    if required is not None and len(key) < required:
        findings.append(_finding(KEY_SIZE_WEAK, "HMAC key material is too short for its declared algorithm", "k"))
    return findings


def _validate_key_type_parameters(obj: Mapping[str, Any], kty: str) -> List[Finding]:
    if kty == "RSA":
        return _validate_rsa(obj)
    if kty == "EC":
        return _validate_ec(obj)
    if kty == "OKP":
        return _validate_okp(obj)
    if kty == "oct":
        return _validate_oct(obj)
    return [_finding(KTY_UNSUPPORTED, "key type is unsupported", "kty")]


def _audit_jwk_object(obj: Mapping[str, Any], *, public: bool, expected_use: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    if len(obj) > 64:
        findings.append(_finding(JWK_INVALID, "JWK has too many member parameters"))
    kty = obj.get("kty")
    if not isinstance(kty, str) or not kty:
        findings.append(_finding(KTY_UNSUPPORTED, "kty is required", "kty"))
    elif kty not in {"RSA", "EC", "OKP", "oct"}:
        findings.append(_finding(KTY_UNSUPPORTED, "kty is unsupported", "kty"))
    else:
        findings.extend(_validate_key_type_parameters(obj, kty))

    if public:
        for field in sorted(PRIVATE_FIELDS):
            if field in obj:
                findings.append(_finding(PRIVATE_MATERIAL, "private or symmetric key material must not appear in a public key", field))

    if "kid" in obj:
        kid_finding = _validate_kid(obj.get("kid"))
        if kid_finding is not None:
            findings.append(kid_finding)

    if "alg" in obj:
        findings.extend(_validate_algorithm_value(obj.get("alg")))
        algorithm = obj.get("alg")
        if isinstance(kty, str) and isinstance(algorithm, str):
            family = _key_family_for_algorithm(algorithm)
            if family is not None and family != kty:
                findings.append(_finding(ALG_CONFUSION, "algorithm family does not match key type", "alg"))

    findings.extend(_validate_use_and_ops(obj, expected_use))

    if "x5c" in obj:
        x5c_finding = _validate_x5c(obj.get("x5c"))
        if x5c_finding is not None:
            findings.append(x5c_finding)
    for field in ("x5t", "x5t#S256"):
        if field in obj:
            try:
                decoded = b64url_decode(obj.get(field), field, max_bytes=64)
                expected = 20 if field == "x5t" else 32
                if len(decoded) != expected:
                    findings.append(_finding(KEY_PARAMETER_INVALID, "certificate thumbprint has the wrong length", field))
            except JwkCageError as exc:
                findings.append(_error_to_finding(exc))
    return findings


def audit_jwk(jwk: Any, *, public: bool = True, expected_use: Optional[str] = "sig") -> AuditReport:
    """Audit one JWK and return stable findings without raising."""
    try:
        obj = _copy_object(jwk, max_size=32768, max_nodes=512)
    except JwkCageError as exc:
        return make_report("jwk", [_error_to_finding(exc)], key_count=0)
    findings = _audit_jwk_object(obj, public=public, expected_use=expected_use)
    details: Dict[str, Any] = {"key_count": 1}
    if isinstance(obj.get("kty"), str):
        details["kty"] = obj["kty"]
    if isinstance(obj.get("kid"), str):
        details["kid_present"] = True
    else:
        details["kid_present"] = False
    return make_report("jwk", findings, **details)


def parse_jwk(data: Any, *, allow_private: bool = False, max_input_size: int = 32768) -> Dict[str, Any]:
    """Strictly parse and policy-check one JWK.

    Private or symmetric secret material is rejected unless ``allow_private``
    is explicitly true. The return value is a deep copy detached from the
    caller supplied object.
    """
    if not isinstance(max_input_size, int) or isinstance(max_input_size, bool) or max_input_size < 256:
        raise JwkCageError(CONFIG_INVALID, "max_input_size must be an integer of at least 256")
    try:
        obj = _copy_object(data, max_size=max_input_size, max_nodes=512)
    except JwkCageError:
        raise
    findings = _audit_jwk_object(obj, public=not allow_private, expected_use=None)
    if findings:
        first = findings[0]
        raise JwkCageError(first.code, first.message, first.field)
    return deep_copy_json(obj)


def _coerce_jwks_object(jwks: Any) -> Dict[str, Any]:
    return _copy_object(jwks, max_size=262144, max_nodes=4096)


def audit_jwks(jwks: Any, *, public: bool = True, max_keys: int = 100) -> AuditReport:
    """Audit a complete JSON Web Key Set."""
    if not isinstance(max_keys, int) or isinstance(max_keys, bool) or not 1 <= max_keys <= 1000:
        return make_report("jwks", [_finding(CONFIG_INVALID, "max_keys must be an integer from 1 to 1000")], key_count=0)
    try:
        obj = _coerce_jwks_object(jwks)
    except JwkCageError as exc:
        return make_report("jwks", [_error_to_finding(exc)], key_count=0)
    findings: List[Finding] = []
    unknown = sorted(set(obj) - {"keys"})
    if unknown:
        findings.append(_finding(JWKS_INVALID, "JWKS contains unknown top-level members", "keys"))
    keys = obj.get("keys")
    if not isinstance(keys, list) or not keys:
        findings.append(_finding(JWKS_INVALID, "JWKS keys must be a non-empty array", "keys"))
        return make_report("jwks", findings, key_count=0)
    if len(keys) > max_keys:
        findings.append(_finding(JWKS_INVALID, "JWKS contains too many keys", "keys"))
    limited_keys = keys[:max_keys]

    seen_kids: Dict[str, int] = {}
    seen_casefold: Dict[str, int] = {}
    seen_thumbprints: Dict[str, int] = {}
    missing_kid_count = 0
    for index, item in enumerate(limited_keys):
        if not isinstance(item, dict):
            findings.append(_finding(JWKS_INVALID, "every JWKS key must be an object", "keys", index))
            continue
        key_report_findings = _audit_jwk_object(item, public=public, expected_use="sig")
        for item_finding in key_report_findings:
            findings.append(
                _finding(item_finding.code, item_finding.message, item_finding.field, index)
            )
        kid = item.get("kid")
        if isinstance(kid, str) and _validate_kid(kid) is None:
            if kid in seen_kids:
                findings.append(_finding(KID_DUPLICATE, "JWKS contains a duplicate kid", "kid", index))
            else:
                seen_kids[kid] = index
            folded = kid.casefold()
            if folded in seen_casefold and seen_casefold[folded] != seen_kids.get(kid, index):
                findings.append(_finding(KID_COLLISION, "JWKS contains case-colliding key identifiers", "kid", index))
            elif folded not in seen_casefold:
                seen_casefold[folded] = index
        else:
            missing_kid_count += 1
        try:
            thumbprint = compute_jwk_thumbprint(item)
        except JwkCageError:
            thumbprint = None
        if thumbprint:
            if thumbprint in seen_thumbprints and seen_thumbprints[thumbprint] != index:
                findings.append(_finding(KID_COLLISION, "JWKS contains duplicate public key material", "kty", index))
            else:
                seen_thumbprints[thumbprint] = index
    if missing_kid_count > 1:
        findings.append(_finding(KID_REQUIRED, "multiple keys without kid make selection ambiguous", "kid"))
    details: Dict[str, Any] = {"key_count": len(keys), "kids_present": len(seen_kids)}
    return make_report("jwks", findings, **details)


def _validate_header_text(value: Any, field: str, *, max_length: int = 256) -> Optional[Finding]:
    if not isinstance(value, str):
        return _finding(HEADER_INVALID, "header parameter must be a string", field)
    if not value or len(value) > max_length or value != value.strip():
        return _finding(HEADER_INVALID, "header parameter string is empty, oversized or noncanonical", field)
    if any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value):
        return _finding(HEADER_INVALID, "header parameter contains control characters", field)
    return None


def _audit_crit(value: Any) -> List[Finding]:
    if not isinstance(value, list) or not value or len(value) > 8:
        return [_finding(CRIT_INVALID, "crit must be a small non-empty array", "crit")]
    findings: List[Finding] = []
    seen = set()
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 64:
            findings.append(_finding(CRIT_INVALID, "crit entries must be short non-empty strings", "crit"))
            continue
        if item in seen:
            findings.append(_finding(CRIT_INVALID, "crit entries must be unique", "crit"))
        seen.add(item)
        if item in REGISTERED_CRIT_NAMES:
            findings.append(_finding(CRIT_INVALID, "crit must not name a registered JOSE header", "crit"))
        findings.append(_finding(CRIT_UNSUPPORTED, "critical JOSE extensions are not implemented by this firewall", "crit"))
    return findings


def audit_jwt_header(header: Any, *, allow_remote_key_urls: bool = False) -> AuditReport:
    """Audit a JWS or JWE protected header without trusting or fetching it."""
    try:
        obj = _copy_object(header, max_size=16384, max_nodes=256)
    except JwkCageError as exc:
        return make_report("jwt-header", [_error_to_finding(exc)])
    findings: List[Finding] = []
    if len(obj) > 64:
        findings.append(_finding(HEADER_INVALID, "JOSE header has too many members"))
    if "alg" not in obj:
        findings.append(_finding(ALG_UNSUPPORTED, "alg is required", "alg"))
    else:
        findings.extend(_validate_algorithm_value(obj.get("alg"), "alg"))

    if "kid" in obj:
        kid_finding = _validate_kid(obj.get("kid"))
        if kid_finding is not None:
            findings.append(kid_finding)

    for field in ("jwk", "x5c"):
        if field in obj:
            findings.append(_finding(HEADER_FORBIDDEN, "inline key material in a token header is forbidden", field))
    for field in ("jku", "x5u"):
        if field not in obj:
            continue
        if not allow_remote_key_urls:
            findings.append(_finding(REMOTE_KEY_REFERENCE, "token-controlled remote key references are forbidden", field))
        url_problem = audit_https_url(obj.get(field))
        if url_problem is not None:
            _code, message = url_problem
            findings.append(_finding(REMOTE_URL_UNSAFE, message, field))

    for field in ("typ", "cty"):
        if field in obj:
            text_finding = _validate_header_text(obj.get(field), field)
            if text_finding is not None:
                findings.append(text_finding)
    if "crit" in obj:
        findings.extend(_audit_crit(obj.get("crit")))

    algorithm_value = obj.get("alg")
    is_jwe_algorithm = isinstance(algorithm_value, str) and algorithm_value in (
        JWE_RSA_ALGORITHMS | JWE_EC_ALGORITHMS | JWE_OCT_ALGORITHMS | WEAK_JWE_ALGORITHMS
    )
    is_signing_algorithm = isinstance(algorithm_value, str) and algorithm_value in SIGNING_ALGORITHMS
    if is_jwe_algorithm and "enc" not in obj:
        findings.append(_finding(HEADER_INVALID, "JWE key management algorithms require enc", "enc"))
    if is_signing_algorithm and "enc" in obj:
        findings.append(_finding(HEADER_INVALID, "JWS signing headers must not contain enc", "enc"))
    if is_jwe_algorithm and algorithm_value in JWE_EC_ALGORITHMS and "epk" not in obj:
        findings.append(_finding(HEADER_INVALID, "ECDH-ES headers require a validated epk", "epk"))
    if "enc" in obj:
        enc = obj.get("enc")
        if not isinstance(enc, str) or enc not in JWE_ENC_ALGORITHMS:
            findings.append(_finding(ALG_UNSUPPORTED, "JWE content encryption algorithm is not approved", "enc"))
    if "zip" in obj:
        findings.append(_finding(HEADER_FORBIDDEN, "compressed JWE content is forbidden", "zip"))
    if "epk" in obj:
        epk = obj.get("epk")
        if not isinstance(epk, dict):
            findings.append(_finding(HEADER_INVALID, "epk must be a public JWK object", "epk"))
        else:
            epk_findings = _audit_jwk_object(epk, public=True, expected_use="enc")
            if epk_findings:
                findings.append(_finding(HEADER_INVALID, "epk is not a clean public encryption key", "epk"))
    for field in ("apu", "apv", "iv", "tag", "p2s"):
        if field in obj:
            try:
                b64url_decode(obj.get(field), field, max_bytes=512, allow_empty=True)
            except JwkCageError as exc:
                findings.append(_error_to_finding(exc))
    if "p2c" in obj:
        p2c = obj.get("p2c")
        if not isinstance(p2c, int) or isinstance(p2c, bool) or not 1000 <= p2c <= 1000000:
            findings.append(_finding(HEADER_INVALID, "p2c must be an integer from 1000 to 1000000", "p2c"))
    for field in ("x5t", "x5t#S256"):
        if field in obj:
            try:
                decoded = b64url_decode(obj.get(field), field, max_bytes=64)
                expected = 20 if field == "x5t" else 32
                if len(decoded) != expected:
                    findings.append(_finding(HEADER_INVALID, "certificate thumbprint has the wrong length", field))
            except JwkCageError as exc:
                findings.append(_error_to_finding(exc))
    return make_report("jwt-header", findings, member_count=len(obj))


def strip_private_material(jwk: Any) -> Dict[str, Any]:
    """Return a recursive copy with private and symmetric secret members removed."""
    def strip_value(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): strip_value(child)
                for key, child in value.items()
                if key not in PRIVATE_FIELDS
            }
        if isinstance(value, list):
            return [strip_value(child) for child in value]
        if isinstance(value, tuple):
            return [strip_value(child) for child in value]
        return value

    if not isinstance(jwk, Mapping):
        raise JwkCageError(JWK_INVALID, "strip_private_material requires a mapping")
    result = strip_value(jwk)
    validate_json_tree(result)
    return result


def compute_jwk_thumbprint(jwk: Any) -> str:
    """Compute the RFC 7638 SHA-256 thumbprint of a public JWK."""
    if not isinstance(jwk, Mapping):
        raise JwkCageError(THUMBPRINT_INVALID, "thumbprint input must be a JWK object")
    obj = deep_copy_json(dict(jwk))
    kty = obj.get("kty")
    if kty == "RSA":
        required_names = ("e", "kty", "n")
    elif kty == "EC":
        required_names = ("crv", "kty", "x", "y")
    elif kty == "OKP":
        required_names = ("crv", "kty", "x")
    elif kty == "oct":
        raise JwkCageError(THUMBPRINT_INVALID, "HMAC key thumbprints are not computed because k is secret")
    else:
        raise JwkCageError(THUMBPRINT_INVALID, "thumbprint key type is unsupported", "kty")
    if any(name not in obj for name in required_names):
        raise JwkCageError(THUMBPRINT_INVALID, "thumbprint required public members are missing")
    required = {name: obj[name] for name in required_names}
    for name in required_names:
        if not isinstance(required[name], str):
            raise JwkCageError(THUMBPRINT_INVALID, "thumbprint required members must be strings", name)
    try:
        for name in set(required_names) - {"kty", "crv"}:
            b64url_decode(required[name], name, max_bytes=4096)
    except JwkCageError as exc:
        raise JwkCageError(THUMBPRINT_INVALID, "thumbprint members must be canonical base64url", exc.field) from exc
    canonical = compact_json(required).encode("utf-8")
    return b64url_encode(hashlib.sha256(canonical).digest())


def _coerce_allowed_algorithms(allowed_algs: Optional[Iterable[str]]) -> Tuple[str, ...]:
    if allowed_algs is None:
        return tuple(sorted(SIGNING_ALGORITHMS))
    if isinstance(allowed_algs, (str, bytes, bytearray)):
        raise JwkCageError(CONFIG_INVALID, "allowed_algs must be a sequence of algorithm names")
    try:
        result = tuple(allowed_algs)
    except TypeError as exc:
        raise JwkCageError(CONFIG_INVALID, "allowed_algs must be a sequence of algorithm names") from exc
    if not result:
        raise JwkCageError(CONFIG_INVALID, "allowed_algs must not be empty")
    for algorithm in result:
        if not isinstance(algorithm, str) or algorithm not in SIGNING_ALGORITHMS:
            raise JwkCageError(CONFIG_INVALID, "allowed_algs may contain only approved signing algorithms")
    if len(set(result)) != len(result):
        raise JwkCageError(CONFIG_INVALID, "allowed_algs must not contain duplicates")
    return result


def _key_matches_algorithm(key: Mapping[str, Any], algorithm: str) -> bool:
    family = _key_family_for_algorithm(algorithm)
    if family != key.get("kty"):
        return False
    if algorithm in EC_ALGORITHMS:
        expected_curve = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[algorithm]
        if key.get("crv") != expected_curve:
            return False
    if algorithm in OKP_ALGORITHMS and key.get("crv") not in OKP_CURVE_SIZES:
        return False
    key_algorithm = key.get("alg")
    if key_algorithm is not None and key_algorithm != algorithm:
        return False
    use = key.get("use")
    if use is not None and use != "sig":
        return False
    key_ops = key.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        return False
    if algorithm in HMAC_ALGORITHMS:
        try:
            secret = b64url_decode(key.get("k"), "k", max_bytes=512)
        except JwkCageError:
            return False
        required = {"HS256": 32, "HS384": 48, "HS512": 64}[algorithm]
        if len(secret) < required:
            return False
    return True


def _public_verification_copy(key: Mapping[str, Any], algorithm: str) -> Dict[str, Any]:
    copied = deep_copy_json(dict(key))
    if _key_family_for_algorithm(algorithm) == "oct":
        for field in RSA_PRIVATE_FIELDS:
            copied.pop(field, None)
        return copied
    return strip_private_material(copied)


def select_verification_key(
    jwks: Any,
    header: Any,
    *,
    allowed_algs: Optional[Iterable[str]] = None,
    require_kid: bool = True,
) -> Dict[str, Any]:
    """Select exactly one key for JWS verification or raise ``JwkCageError``.

    This function never reads inline keys and never fetches ``jku`` or ``x5u``.
    It returns key material suitable for verification. HMAC keys retain ``k``
    because HMAC verification is impossible without the shared secret; all RSA
    private members are removed.
    """
    allowed = _coerce_allowed_algorithms(allowed_algs)
    header_report = audit_jwt_header(header)
    header_report.raise_for_errors()
    try:
        header_obj = _copy_object(header, max_size=16384, max_nodes=256)
    except JwkCageError:
        raise
    algorithm = header_obj.get("alg")
    if algorithm not in SIGNING_ALGORITHMS:
        raise JwkCageError(ALG_UNSUPPORTED, "header algorithm is not an approved signing algorithm", "alg")
    if algorithm not in allowed:
        raise JwkCageError(ALG_NOT_ALLOWED, "header algorithm is not in the caller allowlist", "alg")

    jwks_report = audit_jwks(jwks, public=False)
    jwks_report.raise_for_errors()
    jwks_obj = _coerce_jwks_object(jwks)
    keys = jwks_obj["keys"]

    kid = header_obj.get("kid")
    if kid is None:
        if require_kid:
            raise JwkCageError(KID_REQUIRED, "verification key selection requires a kid", "kid")
        candidates = [key for key in keys if _key_matches_algorithm(key, algorithm)]
    else:
        candidates = [key for key in keys if key.get("kid") == kid and _key_matches_algorithm(key, algorithm)]
    if not candidates:
        raise JwkCageError(KEY_NOT_FOUND, "no verification key matches the strict header policy")
    if len(candidates) > 1:
        raise JwkCageError(KEY_AMBIGUOUS, "more than one verification key matches the strict header policy")
    return _public_verification_copy(candidates[0], algorithm)


__all__ = [
    "CURVES",
    "EC_ALGORITHMS",
    "HMAC_ALGORITHMS",
    "JOSE_ALGORITHMS",
    "JWE_ENC_ALGORITHMS",
    "OKP_ALGORITHMS",
    "PRIVATE_FIELDS",
    "RSA_ALGORITHMS",
    "SIGNING_ALGORITHMS",
    "audit_jwk",
    "audit_jwks",
    "audit_jwt_header",
    "compute_jwk_thumbprint",
    "parse_jwk",
    "select_verification_key",
    "strip_private_material",
]
