"""Portable CLI smoke checks for pyjwkcage (stdlib only, Python 3.9+).

Exercises --version, a rejected weak RSA fixture, the JSON report shape,
and the expected exit codes 0, 1 and 2. Run from anywhere:

    python3 scripts/check_cli.py

Exits 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WEAK_RSA = {"kty": "RSA", "kid": "smoke", "use": "sig", "alg": "RS256", "n": "g", "e": "AQAB"}


def run_cli(args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    return subprocess.run(
        [sys.executable, "-m", "pyjwkcage"] + args,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def check(name, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + name + ((" — " + detail) if detail and not condition else ""))
    return condition


def main() -> int:
    ok = True

    version = run_cli(["--version"])
    ok &= check("version exits 0", version.returncode == 0, "got %s" % version.returncode)
    ok &= check(
        "version names the tool",
        version.stdout.strip().startswith("pyjwkcage "),
        version.stdout.strip(),
    )

    with tempfile.TemporaryDirectory() as tmp:
        fixture = Path(tmp) / "weak-key.json"
        fixture.write_text(json.dumps(WEAK_RSA), encoding="utf-8")
        audit = run_cli(["audit-jwk", str(fixture), "--json"])
        ok &= check("weak RSA fixture exits 1", audit.returncode == 1, "got %s" % audit.returncode)
        try:
            report = json.loads(audit.stdout)
        except ValueError:
            report = None
        ok &= check("audit output is JSON", report is not None, audit.stdout[:120])
        if report is not None:
            ok &= check(
                "JSON report shape",
                {"subject", "ok", "findings", "error_codes", "details"} <= set(report)
                and report["ok"] is False
                and len(report["findings"]) > 0,
                json.dumps(report)[:200],
            )

    usage = run_cli([])
    ok &= check("missing command exits 2", usage.returncode == 2, "got %s" % usage.returncode)

    print("CLI smoke checks " + ("passed" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
