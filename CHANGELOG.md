# Changelog

## Unreleased

- Add `scripts/check_cli.py`, a standard-library-only CLI smoke test that CI now runs instead of inline shell logic.

## 1.0.0

Initial release.

- Strict RFC 7517 JWK and JWKS parsing and auditing.
- RFC 7518 algorithm family, key size, curve, key use and key operation policy checks.
- RFC 7638 SHA-256 thumbprints.
- JWS and JWE header firewall checks for key injection, remote key references, unsafe key identifiers and weak algorithms.
- Offline HTTPS endpoint policy checks for remote key references.
- Command line interface and runnable examples.
