"""Command line interface for offline key-set audits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from .core import (
    audit_jwk,
    audit_jwks,
    audit_jwt_header,
    compute_jwk_thumbprint,
    strip_private_material,
)
from .errors import JwkCageError
from .jsonutil import parse_json_object

MAX_INPUT_FILE = 262144


def _read_json_file(path_text: str) -> Any:
    path = Path(path_text)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise JwkCageError("INPUT_INVALID", "input file cannot be read") from exc
    if len(data) > MAX_INPUT_FILE:
        raise JwkCageError("INPUT_INVALID", "input file is too large")
    return parse_json_object(data, max_size=MAX_INPUT_FILE, max_nodes=4096)


def _print_report(report: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        status = "ok" if report.ok else "rejected"
        print("{}: {}".format(report.subject, status))
        for finding in report.findings:
            location = ""
            if finding.key_index is not None:
                location += " key[{}]".format(finding.key_index)
            if finding.field:
                location += " " + finding.field
            print("{} {}{}: {}".format(finding.severity, finding.code, location, finding.message))


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="pyjwkcage",
        description="Offline JWK, JWKS and JOSE header security firewall.",
    )
    parser.add_argument("--version", action="version", version="pyjwkcage {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_json_flag(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--json", action="store_true", dest="as_json", help="emit machine readable JSON")

    jwk_parser = subparsers.add_parser("audit-jwk", help="audit one JWK JSON object")
    jwk_parser.add_argument("file")
    jwk_parser.add_argument("--allow-private", action="store_true", help="input is a trusted local key, not a public key")
    add_json_flag(jwk_parser)

    jwks_parser = subparsers.add_parser("audit-jwks", help="audit a JWKS document")
    jwks_parser.add_argument("file")
    jwks_parser.add_argument("--allow-private", action="store_true", help="input is a trusted local key set, not a public key set")
    jwks_parser.add_argument("--max-keys", type=int, default=100)
    add_json_flag(jwks_parser)

    header_parser = subparsers.add_parser("audit-header", help="audit a JWS or JWE protected header")
    header_parser.add_argument("file")
    header_parser.add_argument("--allow-remote-key-urls", action="store_true", help="audit rather than forbid jku and x5u references")
    add_json_flag(header_parser)

    thumbprint_parser = subparsers.add_parser("thumbprint", help="print the RFC 7638 SHA-256 key thumbprint")
    thumbprint_parser.add_argument("file")

    strip_parser = subparsers.add_parser("strip-private", help="print a public copy without private or symmetric material")
    strip_parser.add_argument("file")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit-jwk":
            report = audit_jwk(_read_json_file(args.file), public=not args.allow_private, expected_use=None)
            _print_report(report, args.as_json)
            return 0 if report.ok else 1
        if args.command == "audit-jwks":
            report = audit_jwks(_read_json_file(args.file), public=not args.allow_private, max_keys=args.max_keys)
            _print_report(report, args.as_json)
            return 0 if report.ok else 1
        if args.command == "audit-header":
            report = audit_jwt_header(
                _read_json_file(args.file),
                allow_remote_key_urls=args.allow_remote_key_urls,
            )
            _print_report(report, args.as_json)
            return 0 if report.ok else 1
        if args.command == "thumbprint":
            print(compute_jwk_thumbprint(_read_json_file(args.file)))
            return 0
        if args.command == "strip-private":
            print(json.dumps(strip_private_material(_read_json_file(args.file)), indent=2, sort_keys=True))
            return 0
    except JwkCageError as exc:
        print("pyjwkcage: error: {}".format(exc), file=sys.stderr)
        return 1
    parser.error("unknown command")
    return 2


__all__ = ["build_parser", "main"]
