from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_cli.py"


def load_script():
    spec = importlib.util.spec_from_file_location("pyjwkcage_check_cli", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


FAKE_CLI = textwrap.dedent(
    """
    import json
    import sys

    args = sys.argv[1:]
    if args == ["--version"]:
        print("pyjwkcage 1.0.0")
        raise SystemExit(0)
    if args and args[0] == "audit-jwk":
        print(json.dumps({"subject": "jwk", "ok": True, "findings": [], "error_codes": [], "details": {}}))
        raise SystemExit(0)
    raise SystemExit(0)
    """
)


class TestCheckCliScript(unittest.TestCase):
    def test_script_passes_against_source_tree(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=str(REPO),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"CLI smoke checks passed", result.stdout)

    def test_script_reports_a_cli_that_accepts_weak_keys_and_bad_usage(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake_cli.py"
            fake.write_text(FAKE_CLI, encoding="utf-8")
            errors = module.run_checks([sys.executable, str(fake)])
        joined = "\n".join(errors)
        self.assertIn("audit-jwk weak RSA key: expected exit code 1, got 0", joined)
        self.assertIn("missing subcommand: expected exit code 2, got 0", joined)
        self.assertIn("unknown subcommand: expected exit code 2, got 0", joined)
        self.assertNotIn("--version", joined)
        self.assertNotIn("strong RSA key", joined)

    def test_report_shape_rejects_missing_keys(self):
        module = load_script()
        errors = []
        module._check_report_shape(errors, "shape", '{"ok": false, "findings": []}')
        self.assertEqual(len(errors), 1)
        self.assertIn("report keys", errors[0])

    def test_report_shape_rejects_malformed_finding(self):
        module = load_script()
        errors = []
        stdout = '{"subject": "jwk", "ok": false, "findings": [{"code": "X"}], "error_codes": ["X"], "details": {}}'
        module._check_report_shape(errors, "shape", stdout)
        self.assertEqual(len(errors), 1)
        self.assertIn("findings[0]", errors[0])

    def test_script_does_not_use_a_shell(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

    def test_ci_workflow_runs_the_script(self):
        data = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/check_cli.py", data)
        self.assertNotIn("pyjwkcage-ci-key.json", data)


if __name__ == "__main__":
    unittest.main()
