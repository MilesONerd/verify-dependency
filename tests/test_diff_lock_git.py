# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""diff_lock.py CLI: --git mode in subdirectories, --base refs, and error handling (never a silent 'everything added')."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts", "diff_lock.py")
OLD = json.dumps({"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}, "node_modules/b": {"version": "2.0.0"}}})
NEW = json.dumps({"packages": {"": {}, "node_modules/a": {"version": "1.1.0"}, "node_modules/c": {"version": "3.0.0"}}})
SUMMARY = {"added": 1, "removed": 1, "changed": 1}


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def run(*args, cwd):
    p = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, cwd=cwd)
    return p.returncode, json.loads(p.stdout)


@unittest.skipUnless(shutil.which("git"), "git not available")
class GitMode(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.git("init", "-q", ".")
        self.lock = os.path.join(self.root, "my dir", "pkg", "package-lock.json")  # subdirectory with a space
        write(self.lock, OLD)
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.git("tag", "v1")
        write(self.lock, NEW)

    def git(self, *a):
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=self.root, check=True, capture_output=True)

    def test_from_repo_root_with_subdirectory_path(self):
        code, out = run("--git", "my dir/pkg/package-lock.json", cwd=self.root)
        self.assertEqual((code, out["summary"]), (0, SUMMARY))

    def test_from_inside_the_subdirectory(self):
        code, out = run("--git", "package-lock.json", cwd=os.path.dirname(self.lock))
        self.assertEqual((code, out["summary"]), (0, SUMMARY))

    def test_absolute_path_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory() as other:
            code, out = run("--git", self.lock, cwd=other)
        self.assertEqual((code, out["summary"]), (0, SUMMARY))

    def test_base_ref_compares_against_an_older_commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "update")
        _, vs_head = run("--git", self.lock, cwd=self.root)
        self.assertEqual(vs_head["summary"], {"added": 0, "removed": 0, "changed": 0})
        _, vs_tag = run("--git", self.lock, "--base", "v1", cwd=self.root)
        self.assertEqual(vs_tag["summary"], SUMMARY)

    def test_unknown_ref_is_an_error_not_everything_added(self):
        code, out = run("--git", self.lock, "--base", "no-such-ref", cwd=self.root)
        self.assertEqual((code, out["status"]), (2, "error"))
        self.assertIn("unknown git ref", out["error"])

    def test_file_untracked_at_ref_is_reported_as_all_added_with_a_note(self):
        fresh = os.path.join(self.root, "other", "package-lock.json")
        write(fresh, NEW)
        code, out = run("--git", fresh, cwd=self.root)
        self.assertEqual(code, 0)
        self.assertIn("not found at HEAD", out["note"])
        self.assertEqual(out["summary"]["added"], 2)

    def test_missing_file_is_an_error(self):
        code, out = run("--git", "nope/package-lock.json", cwd=self.root)
        self.assertEqual((code, out["status"]), (2, "error"))
        self.assertIn("cannot read", out["error"])


class OutsideGit(unittest.TestCase):
    def test_not_a_repository_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            write(os.path.join(t, "package-lock.json"), NEW)
            code, out = run("--git", "package-lock.json", cwd=t)
        self.assertEqual((code, out["status"]), (2, "error"))
        self.assertIn("not inside a git repository", out["error"])

    def test_parse_warning_when_nonempty_lockfile_yields_no_packages(self):
        with tempfile.TemporaryDirectory() as t:
            odd = "unexpected: content\nwith: no recognizable lockfile markers\n"
            write(os.path.join(t, "old.yaml"), odd)
            write(os.path.join(t, "pnpm-lock.yaml"), odd)
            code, out = run(os.path.join(t, "old.yaml"), os.path.join(t, "pnpm-lock.yaml"), cwd=t)
        self.assertEqual(code, 0)
        self.assertTrue(out["parse_warning"])

    def test_no_warning_for_a_legitimately_empty_json_lockfile(self):
        with tempfile.TemporaryDirectory() as t:
            write(os.path.join(t, "old.json"), json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}}}))
            write(os.path.join(t, "package-lock.json"), NEW)
            code, out = run(os.path.join(t, "old.json"), os.path.join(t, "package-lock.json"), cwd=t)
        self.assertEqual(code, 0)
        self.assertNotIn("parse_warning", out)
        self.assertEqual(out["summary"]["added"], 2)

    def test_no_warning_for_recognized_formats_without_third_party_packages(self):
        """Real empty lockfiles of a brand-new project (generated by uv 0.11, Poetry 2.5, pnpm 12)."""
        empties = {
            "uv.lock": 'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n',
            "poetry.lock": '# This file is automatically @generated by Poetry 2.5.1 and should not be changed by hand.\npackage = []\n\n[metadata]\nlock-version = "2.1"\n',
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n",
            "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n",
        }
        for name, text in empties.items():
            with self.subTest(lockfile=name), tempfile.TemporaryDirectory() as t:
                write(os.path.join(t, "old-" + name), text)
                write(os.path.join(t, name), text)
                code, out = run(os.path.join(t, "old-" + name), os.path.join(t, name), cwd=t)
                self.assertEqual(code, 0)
                self.assertNotIn("parse_warning", out)


if __name__ == "__main__":
    unittest.main()
