"""Repository hygiene tests driven by git ls-files with a safe fallback."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def tracked_files():
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(REPO),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return [
                REPO / part.decode("utf-8")
                for part in result.stdout.split(b"\x00")
                if part and not part.startswith(b".git/") and b"__pycache__" not in part and not part.endswith((b".pyc", b".pyo"))
            ]
    except (OSError, subprocess.SubprocessError):
        pass
    output = []
    for root, dirs, files in os.walk(str(REPO)):
        dirs[:] = [
            item
            for item in dirs
            if item not in (".git", "__pycache__", "build", "dist") and not item.endswith(".egg-info")
        ]
        for name in files:
            if name.endswith((".pyc", ".pyo")) or name == ".DS_Store":
                continue
            output.append(Path(root) / name)
    return output


class TestRepositoryHygiene(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = tracked_files()
        cls.text_files = []
        for path in cls.files:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" not in data:
                cls.text_files.append((path, data))

    def test_file_inventory_nonempty(self):
        self.assertGreater(len(self.files), 20)

    def test_no_em_dash_bytes(self):
        needle = b"\xe2\x80\x94"
        offenders = [str(path) for path, data in self.text_files if needle in data]
        self.assertEqual(offenders, [])

    def test_no_en_dash_bytes(self):
        needle = b"\xe2\x80\x93"
        offenders = [str(path) for path, data in self.text_files if needle in data]
        self.assertEqual(offenders, [])

    def test_no_posix_user_paths(self):
        needle = ("/" + "Users" + "/").encode("ascii")
        offenders = [str(path) for path, data in self.text_files if needle in data]
        self.assertEqual(offenders, [])

    def test_no_windows_user_paths(self):
        needle = ("\\" + "Users" + "\\").encode("ascii")
        offenders = [str(path) for path, data in self.text_files if needle in data]
        self.assertEqual(offenders, [])

    def test_no_common_personal_mailbox_fragments(self):
        fragments = [
            ("someone" + "@").encode("ascii"),
            ("handle-redacted" + "@").encode("ascii"),
            ("gmail" + ".com").encode("ascii"),
        ]
        offenders = []
        for path, data in self.text_files:
            if any(fragment in data.lower() for fragment in fragments):
                offenders.append(str(path))
        self.assertEqual(offenders, [])

    def test_no_coauthored_trailer_text(self):
        needle = ("Co" + "-Authored" + "-By:").encode("ascii")
        offenders = [str(path) for path, data in self.text_files if needle in data]
        self.assertEqual(offenders, [])

    def test_no_key_or_certificate_file_extensions_tracked(self):
        offenders = [str(path) for path in self.files if str(path).endswith((".pem", ".key", ".p12", ".pfx"))]
        self.assertEqual(offenders, [])

    def test_no_bytecode_or_cache_files_tracked(self):
        offenders = [
            str(path)
            for path in self.files
            if "__pycache__" in path.parts or str(path).endswith((".pyc", ".pyo"))
        ]
        self.assertEqual(offenders, [])

    def test_no_build_output_tracked(self):
        offenders = [
            str(path)
            for path in self.files
            if "build" in path.parts or "dist" in path.parts or any(part.endswith(".egg-info") for part in path.parts)
        ]
        self.assertEqual(offenders, [])

    def test_no_vendor_secret_prefixes(self):
        prefixes = [
            ("tskey" + "-auth").encode("ascii"),
            ("sk" + "-").encode("ascii"),
            ("ghp" + "_").encode("ascii"),
            ("github" + "_pat_").encode("ascii"),
            ("AK" + "IA").encode("ascii"),
            ("xox" + "b-").encode("ascii"),
            ("nvapi" + "-").encode("ascii"),
            ("AI" + "za").encode("ascii"),
        ]
        offenders = []
        for path, data in self.text_files:
            if any(prefix in data for prefix in prefixes):
                offenders.append(str(path))
        self.assertEqual(offenders, [])

    def test_pyproject_zero_runtime_dependencies(self):
        data = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "pyjwkcage"', data)
        self.assertIn('version = "1.0.0"', data)
        self.assertIn('requires-python = ">=3.9"', data)
        self.assertIn("dependencies = []", data)
        self.assertIn('pyjwkcage = "pyjwkcage.cli:main"', data)

    def test_publish_workflow_release_only_oidc(self):
        data = (REPO / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("types: [published]", data)
        self.assertIn("environment:", data)
        self.assertIn("name: pypi", data)
        self.assertIn("id-token: write", data)
        self.assertNotIn("workflow_dispatch", data)

    def test_ci_workflow_python_matrix(self):
        data = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', data)
        self.assertIn("ubuntu-24.04", data)
        self.assertIn("python3 scripts/check_dist.py dist", data)

    def test_text_files_use_lf_not_crlf(self):
        offenders = [str(path) for path, data in self.text_files if b"\r\n" in data]
        self.assertEqual(offenders, [])

    def test_no_trailing_whitespace_in_python_files(self):
        offenders = []
        for path, data in self.text_files:
            if path.suffix != ".py":
                continue
            for line in data.split(b"\n"):
                if line.endswith((b" ", b"\t")):
                    offenders.append(str(path))
                    break
        self.assertEqual(offenders, [])

    def test_package_marker_present(self):
        self.assertTrue((REPO / "src" / "pyjwkcage" / "py.typed").is_file())

    def test_no_hidden_local_config_files(self):
        offenders = [
            str(path)
            for path in self.files
            if path.name in (".pypirc", ".netrc", ".npmrc", "id_rsa", "id_ed25519")
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
