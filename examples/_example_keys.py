"""Deterministic public test fixtures for runnable examples."""
from __future__ import annotations

import base64


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def rsa_public_key(kid: str = "example-rsa-2026") -> dict:
    body = bytes((index * 37 + 11) % 256 for index in range(254))
    modulus = b"\x80" + body + b"\x03"
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64u(modulus),
        "e": "AQAB",
    }


def ec_p256_public_key(kid: str = "example-ec-2026") -> dict:
    x_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    y_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": b64u(bytes.fromhex(x_hex)),
        "y": b64u(bytes.fromhex(y_hex)),
    }
