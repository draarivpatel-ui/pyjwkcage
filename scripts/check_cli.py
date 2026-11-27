#!/usr/bin/env python3
"""Portable smoke checks for the pyjwkcage command line interface.

Uses only the standard library, writes fixtures to a temporary directory and
runs the CLI through subprocess with an argument list, never through a shell.
By default the CLI is run as ``python -m pyjwkcage`` against the source tree;
pass a different command after ``--`` to check another entry point.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO = Path(__file__).resolve().parents[1]
TIMEOUT_SECONDS = 30
VERSION_PATTERN = re.compile(r"^pyjwkcage \d+\.\d+\.\d+\S*$")
REPORT_KEYS = frozenset({"subject", "ok", "findings", "error_codes", "details"})
FINDING_KEYS = frozenset({"code", "severity", "message"})
OPTIONAL_FINDING_KEYS = frozenset({"field", "key_index"})


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _rsa_key(bit_length: int) -> Dict[str, str]:
    """Return a deterministic public RSA JWK whose modulus has ``bit_length`` bits."""
    length = (bit_length + 7) // 8
    remainder = bit_length % 8 or 8
    body = bytes((index * 37 + 11) % 256 for index in range(length - 2))
    modulus = bytes([1 << (remainder - 1)]) + body + b"\x03"
    return {
        "kty": "RSA",
        "kid": "cli-smoke",
        "use": "sig",
        "alg": "RS256",
        "n": _b64u(modulus),
        "e": "AQAB",
    }


def default_command() -> List[str]:
    return [sys.executable, "-m", "pyjwkcage"]


def _environment() -> Dict[str, str]:
    env = dict(os.environ)
    source = str(REPO / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source + os.pathsep + existing if existing else source
    return env


def _run(command: Sequence[str], args: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        list(command) + list(args),
        cwd=str(REPO),
        env=_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )


def _expect_exit(
    errors: List[str],
    label: str,
    result: "subprocess.CompletedProcess[str]",
    expected: int,
) -> bool:
    if "Traceback" in result.stderr:
        errors.append(label + ": stderr contains a Python traceback")
    if result.returncode != expected:
        errors.append(
            "{}: expected exit code {}, got {} (stderr: {!r})".format(
                label, expected, result.returncode, result.stderr.strip()
            )
        )
        return False
    return True


def _check_report_shape(errors: List[str], label: str, stdout: str) -> Optional[Dict[str, Any]]:
    try:
        report = json.loads(stdout)
    except ValueError:
        errors.append(label + ": --json output is not valid JSON")
        return None
    if not isinstance(report, dict):
        errors.append(label + ": --json output is not a JSON object")
        return None
    keys = set(report)
    if keys != REPORT_KEYS:
        errors.append("{}: report keys are {}, expected {}".format(label, sorted(keys), sorted(REPORT_KEYS)))
        return None
    if not isinstance(report["subject"], str):
        errors.append(label + ": report subject is not a string")
    if not isinstance(report["ok"], bool):
        errors.append(label + ": report ok is not a boolean")
    if not isinstance(report["details"], dict):
        errors.append(label + ": report details is not an object")
    codes = report["error_codes"]
    if not isinstance(codes, list) or not all(isinstance(code, str) for code in codes):
        errors.append(label + ": report error_codes is not a list of strings")
    findings = report["findings"]
    if not isinstance(findings, list):
        errors.append(label + ": report findings is not a list")
        return report
    for index, finding in enumerate(findings):
        where = "{}: findings[{}]".format(label, index)
        if not isinstance(finding, dict):
            errors.append(where + " is not an object")
            continue
        keys = set(finding)
        if not FINDING_KEYS <= keys or not keys <= FINDING_KEYS | OPTIONAL_FINDING_KEYS:
            errors.append("{} has unexpected keys {}".format(where, sorted(keys)))
            continue
        if not all(isinstance(finding[name], str) for name in FINDING_KEYS):
            errors.append(where + " code, severity and message must be strings")
    return report


def check_version(errors: List[str], command: Sequence[str]) -> None:
    result = _run(command, ["--version"])
    if _expect_exit(errors, "--version", result, 0):
        output = result.stdout.strip()
        if not VERSION_PATTERN.match(output):
            errors.append("--version: unexpected output {!r}".format(output))


def check_strong_key_accepted(errors: List[str], command: Sequence[str], directory: Path) -> None:
    label = "audit-jwk strong RSA key"
    path = directory / "strong-rsa.json"
    path.write_text(json.dumps(_rsa_key(2048)), encoding="utf-8")
    result = _run(command, ["audit-jwk", str(path), "--json"])
    if not _expect_exit(errors, label, result, 0):
        return
    report = _check_report_shape(errors, label, result.stdout)
    if report is not None and (report.get("ok") is not True or report.get("error_codes")):
        errors.append(label + ": report is not ok")


def check_weak_key_rejected(errors: List[str], command: Sequence[str], directory: Path) -> None:
    label = "audit-jwk weak RSA key"
    path = directory / "weak-rsa.json"
    path.write_text(json.dumps(_rsa_key(1024)), encoding="utf-8")
    result = _run(command, ["audit-jwk", str(path), "--json"])
    if not _expect_exit(errors, label, result, 1):
        return
    report = _check_report_shape(errors, label, result.stdout)
    if report is None:
        return
    if report.get("ok") is not False:
        errors.append(label + ": report ok is not false")
    codes = report.get("error_codes")
    if not isinstance(codes, list) or "KEY_SIZE_WEAK" not in codes:
        errors.append(label + ": KEY_SIZE_WEAK missing from error_codes {!r}".format(codes))


def check_usage_errors(errors: List[str], command: Sequence[str]) -> None:
    for label, args in (
        ("missing subcommand", []),
        ("unknown subcommand", ["no-such-command"]),
    ):
        result = _run(command, args)
        if _expect_exit(errors, label, result, 2) and "usage:" not in result.stderr:
            errors.append(label + ": usage message missing from stderr")


def run_checks(command: Optional[Sequence[str]] = None) -> List[str]:
    """Run every smoke check and return a list of failure messages."""
    command = list(command) if command else default_command()
    errors: List[str] = []
    try:
        check_version(errors, command)
        check_usage_errors(errors, command)
        with tempfile.TemporaryDirectory(prefix="pyjwkcage-cli-") as temp:
            directory = Path(temp)
            check_strong_key_accepted(errors, command, directory)
            check_weak_key_rejected(errors, command, directory)
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append("could not run the CLI: {}".format(exc))
    return errors


def main(argv: Sequence[str]) -> int:
    args = list(argv[1:])
    if args and args[0] == "--":
        args = args[1:]
    errors = run_checks(args or None)
    if errors:
        for error in errors:
            print("check_cli: " + error, file=sys.stderr)
        return 1
    print("CLI smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
