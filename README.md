# pyjwkcage

`pyjwkcage` is a zero-dependency Python 3.9+ security firewall for RFC 7517 JSON Web Keys, RFC 7518 key algorithms, JWS headers, JWE headers and public JWKS documents. It is designed for authentication services, token issuers, key rotation pipelines and JWT verification integrations that must treat key sets and token headers as hostile input.

The library is standard library only. It performs no network access and no cryptographic signing or verification. It decides whether key material is structurally valid, internally consistent and safe to hand to a real cryptographic verifier.

## What it blocks

- `alg: none` in every casing and whitespace variant.
- HMAC versus asymmetric key confusion, including `HS256` tokens pointed at RSA, EC or OKP keys.
- RSA moduli below 2048 bits, oversized moduli, malformed modulus or exponent encodings, even exponents and public exponents below 65537.
- Unknown or unapproved EC curves, wrong coordinate sizes, out-of-range coordinates and points that are not on P-256, P-384 or P-521.
- EdDSA keys outside Ed25519 and Ed448.
- Private or symmetric material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k` and `oth`) in public key sets.
- Duplicate key identifiers, case-colliding key identifiers and duplicated public keys in one key set.
- `kid` path traversal, separators, SQL-injection metacharacters, ASCII control bytes, NUL, CRLF, whitespace and invisible Unicode formatting characters.
- Inline `jwk` or `x5c` key material in token headers.
- Token-controlled `jku` and `x5u` remote key references by default. If explicitly enabled for a constrained deployment, only canonical HTTPS URLs on public hosts pass the offline audit.
- Weak, unknown or mismatched `use`, `key_ops`, `alg`, `enc`, `crit` and compression header parameters.
- Duplicate JSON member names, noncanonical base64url, oversized documents, deep nesting, non-finite numbers, unpaired surrogates and parser differentials.

## Install

```bash
python3 -m pip install pyjwkcage
```

For local development, run everything from a checkout with `PYTHONPATH=src`.

## Quick start

```python
from pyjwkcage import audit_jwks, audit_jwt_header, select_verification_key

jwks = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "signing-2026-01",
            "use": "sig",
            "alg": "RS256",
            "n": "unsigned-modulus-base64url",
            "e": "AQAB",
        }
    ]
}

report = audit_jwks(jwks)
if not report.ok:
    raise ValueError(report.error_codes)

header = {"alg": "RS256", "kid": "signing-2026-01", "typ": "JWT"}
assert audit_jwt_header(header).ok
key = select_verification_key(jwks, header, allowed_algs=["RS256"])
```

`select_verification_key` never infers an algorithm family from the key alone in a way that can be confused across families. The token algorithm must be allowed by the caller, the key type must belong to that algorithm family, EC keys must be on the exact curve for the algorithm, and an in-key `alg` must match the header exactly.

## API

### `parse_jwk(data, allow_private=False)`

Strictly parses a JSON object or mapping into a fresh dictionary. By default private or symmetric secret material is rejected. Pass `allow_private=True` only when the input is a trusted local key store rather than a public JWKS.

### `audit_jwk(jwk, public=True, expected_use="sig")`

Audits one key and returns an `AuditReport`. The report contains stable machine readable findings and never echoes secret key bytes.

### `audit_jwks(jwks, public=True, max_keys=100)`

Audits a complete key set, including per-key policy, duplicate key identifiers, case-colliding identifiers and duplicate public keys.

### `audit_jwt_header(header, allow_remote_key_urls=False)`

Audits a JWS or JWE protected header. Inline key material is always rejected. Token-controlled remote key references are rejected unless explicitly enabled, and even then they must be syntactically canonical HTTPS URLs on public hosts. The library still never fetches them.

### `select_verification_key(jwks, header, allowed_algs, require_kid=True)`

Selects exactly one verification key after strict header and key-set validation. HMAC keys must be long enough for the exact HS algorithm. RSA keys must satisfy the modulus and exponent policy. ECDSA keys must use the exact curve for the algorithm. EdDSA keys must use an approved OKP curve.

### `strip_private_material(jwk)`

Returns a recursive copy with `d`, `p`, `q`, `dp`, `dq`, `qi`, `k` and `oth` removed. For HMAC verification, callers normally need `k`; use this function only when producing a public representation.

### `compute_jwk_thumbprint(jwk)`

Computes the RFC 7638 SHA-256 thumbprint and returns base64url text without padding. Required public members are serialized in canonical JSON order. HMAC thumbprints are intentionally unavailable because they would fingerprint secret key bytes.

## CLI

```bash
python3 -m pyjwkcage audit-jwk key.json --json
python3 -m pyjwkcage audit-jwks jwks.json --json
python3 -m pyjwkcage audit-header header.json --json
python3 -m pyjwkcage thumbprint key.json
python3 -m pyjwkcage strip-private key.json
```

Exit status is zero for a clean audit, one for security or structural findings, and two for command line usage errors. Audit output never contains private key material.

## Examples

```bash
PYTHONPATH=src python3 examples/audit_jwks_example.py
PYTHONPATH=src python3 examples/select_key_example.py
PYTHONPATH=src python3 examples/thumbprint_example.py
```

## Threat model boundary

This package is a firewall around key ingestion and key selection. It does not replace a JWS or JWE implementation. It does not fetch `jku` or `x5u`, resolve DNS, pin IP addresses, verify signatures, decrypt content, validate claims, manage key rotation or maintain a trust store. Remote HTTPS validation is offline syntactic and IP-literal policy validation only. A deployment that intentionally uses remote key sets must add resolver pinning, response size limits, caching, TLS validation and issuer allowlisting in a separate audited component.

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 scripts/check_dist.py dist
```

The distribution declares zero runtime dependencies and ships `py.typed`.
