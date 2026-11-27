"""Deterministic fixtures shared by the pyjwkcage test suite."""
from __future__ import annotations

import base64


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def rsa_modulus_bytes(bit_length: int = 2048) -> bytes:
    length = (bit_length + 7) // 8
    if length < 3:
        length = 3
    remainder = bit_length % 8 or 8
    first = bytes([1 << (remainder - 1)])
    body = bytes((index * 37 + 11) % 256 for index in range(max(0, length - 2)))
    return first + body + b"\x03"


def rsa_key(kid: str = "rsa-test", alg: str = "RS256", bit_length: int = 2048, exponent: str = "AQAB") -> dict:
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": b64u(rsa_modulus_bytes(bit_length)),
        "e": exponent,
    }


P256_X = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
P256_Y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
P384_X = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
P384_Y = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
P521_X = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"
P521_Y = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"

EC_POINTS = {
    "P-256": (P256_X, P256_Y, "ES256"),
    "P-384": (P384_X, P384_Y, "ES384"),
    "P-521": (P521_X, P521_Y, "ES512"),
}


def ec_key(crv: str = "P-256", kid: str = "ec-test") -> dict:
    x_hex, y_hex, alg = EC_POINTS[crv]
    return {
        "kty": "EC",
        "crv": crv,
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "x": b64u(bytes.fromhex(x_hex)),
        "y": b64u(bytes.fromhex(y_hex)),
    }


def okp_key(crv: str = "Ed25519", kid: str = "okp-test") -> dict:
    size = 32 if crv == "Ed25519" else 57
    return {
        "kty": "OKP",
        "crv": crv,
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64u(bytes((index * 19 + 7) % 256 for index in range(size))),
    }


def oct_key(size: int = 32, kid: str = "oct-test", alg: str = "HS256") -> dict:
    return {
        "kty": "oct",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "k": b64u(bytes((index * 13 + 5) % 256 for index in range(size))),
    }


RFC7638_KEY = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
