"""Compute an RFC 7638 thumbprint."""
from __future__ import annotations

from pyjwkcage import compute_jwk_thumbprint

from _example_keys import ec_p256_public_key


def main() -> int:
    key = ec_p256_public_key()
    print(compute_jwk_thumbprint(key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
