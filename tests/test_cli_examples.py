from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import rsa_key

REPO = Path(__file__).resolve().parents[1]


def run_command(args, cwd=REPO):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    return subprocess.run(
        [sys.executable] + list(args),
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )


class TestCliAndExamples(unittest.TestCase):
    def write_json(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def test_version(self):
        result = run_command(["-m", "pyjwkcage", "--version"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"pyjwkcage 1.0.0", result.stdout)

    def test_audit_jwks_valid_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "jwks.json", {"keys": [rsa_key()]})
            result = run_command(["-m", "pyjwkcage", "audit-jwks", path, "--json"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(result.stdout.decode())
        self.assertTrue(report["ok"])

    def test_audit_jwks_private_material_fails(self):
        key = rsa_key()
        key["d"] = "AQ"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "jwks.json", {"keys": [key]})
            result = run_command(["-m", "pyjwkcage", "audit-jwks", path, "--json"])
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout.decode())
        self.assertIn("PRIVATE_MATERIAL", report["error_codes"])
        self.assertNotIn("AQ", result.stdout.decode())

    def test_audit_header_remote_reference_fails(self):
        header = {"alg": "RS256", "kid": "a", "jku": "https://127.0.0.1/jwks.json"}
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "header.json", header)
            result = run_command(["-m", "pyjwkcage", "audit-header", path, "--json"])
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout.decode())
        self.assertIn("REMOTE_KEY_REFERENCE", report["error_codes"])

    def test_thumbprint_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "key.json", rsa_key())
            result = run_command(["-m", "pyjwkcage", "thumbprint", path])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertRegex(result.stdout.decode().strip(), r"^[A-Za-z0-9_-]{43}$")

    def test_strip_private_cli(self):
        key = rsa_key()
        key["d"] = "AQ"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "key.json", key)
            result = run_command(["-m", "pyjwkcage", "strip-private", path])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        stripped = json.loads(result.stdout.decode())
        self.assertNotIn("d", stripped)
        self.assertIn("n", stripped)

    def test_examples_run_cleanly(self):
        for name in ("audit_jwks_example.py", "select_key_example.py", "thumbprint_example.py"):
            result = run_command([str(REPO / "examples" / name)])
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr.decode() + result.stdout.decode())

    def test_cli_rejects_malformed_input_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{", encoding="utf-8")
            result = run_command(["-m", "pyjwkcage", "audit-jwk", str(path)])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
