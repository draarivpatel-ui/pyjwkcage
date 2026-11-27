"""Select one verification key without trusting token-controlled key references."""
from __future__ import annotations

from pyjwkcage import select_verification_key

from _example_keys import rsa_public_key


def main() -> int:
    jwks = {"keys": [rsa_public_key()]}
    header = {"alg": "RS256", "kid": "example-rsa-2026", "typ": "JWT"}
    key = select_verification_key(jwks, header, allowed_algs=["RS256"])
    print("selected kid={} kty={} private_members_absent={}".format(
        key["kid"],
        key["kty"],
        all(field not in key for field in ("d", "p", "q", "dp", "dq", "qi", "oth")),
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
