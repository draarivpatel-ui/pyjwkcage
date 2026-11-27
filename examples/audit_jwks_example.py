"""Audit a small public key set offline."""
from __future__ import annotations

import json

from pyjwkcage import audit_jwks

from _example_keys import ec_p256_public_key, rsa_public_key


def main() -> int:
    jwks = {"keys": [rsa_public_key(), ec_p256_public_key()]}
    report = audit_jwks(jwks)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
