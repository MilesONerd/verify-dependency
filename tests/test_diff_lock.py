# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Offline tests for diff_lock.py: one fixture per lockfile format, plus the CLI and the git mode."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts")
sys.path.insert(0, SCRIPTS)
import diff_lock as d  # noqa: E402

NPM_OLD = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/a": {"version": "1.0.0"},
                                                           "node_modules/b": {"version": "2.0.0"}}})
NPM_NEW = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"}, "node_modules/a": {"version": "1.1.0"},
    "node_modules/@s/c": {"version": "3.0.0", "hasInstallScript": True, "resolved": "https://registry.npmjs.org/@s/c/-/c-3.0.0.tgz"},
    "node_modules/a/node_modules/d": {"version": "0.1.0", "resolved": "git+ssh://git@github.com/x/d.git#abc"}}})
CARGO_NEW = ('[[package]]\nname = "myapp"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.2"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "evil"\nversion = "0.0.1"\n'
             'source = "git+https://github.com/x/evil#abc"\n')
UV_NEW = ('[[package]]\nname = "my-proj"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "Charset_Normalizer"\n'
          'version = "3.3.2"\nsource = { registry = "https://pypi.org/simple" }\n')
REQ_NEW = 'requests==2.32.0\nflask[async]==3.0.0 ; python_version>"3.8" --hash=sha256:abc\n# c\n-r other.txt\nfoo>=1\nnumpy==1.26.0 \\\n    --hash=sha256:abc\n'
GOSUM_NEW = "github.com/a/b v1.1.0 h1:x=\ngithub.com/a/b v1.1.0/go.mod h1:y=\ngithub.com/c/d v0.2.0 h1:z=\n"
COMPOSER_NEW = json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.0.0"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}]})
GEM_NEW = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.0)\n      foo (>= 1)\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n"
YARN_NEW = ('# yarn lockfile v1\n\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.20.0"\n  resolved "https://registry.yarnpkg.com/x.tgz"\n\n'
            'lodash@^4.17.0:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/y.tgz"\n')
PNPM_NEW = "lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.20.0':\n    resolution: {integrity: sha512-x}\n  lodash@4.17.21:\n    resolution: {integrity: sha512-y}\nsnapshots:\n  lodash@4.17.21: {}\n"
PIP_REPORT = json.dumps({"version": "1", "install": [{"metadata": {"name": "requests", "version": "2.34.2"}, "requested": True},
                                                    {"metadata": {"name": "Charset_Normalizer", "version": "3.5.2"}}]})


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def names(items):
    return {i["name"] for i in items}


class Parsers(unittest.TestCase):
    def test_npm_lock_v3_with_notes(self):
        added, removed, changed = d.diff(d.p_npm_lock(NPM_OLD), d.p_npm_lock(NPM_NEW))
        self.assertEqual(names(added), {"@s/c", "d"})
        self.assertEqual(names(removed), {"b"})
        self.assertEqual([(c["name"], c["from"], c["to"]) for c in changed], [("a", ["1.0.0"], ["1.1.0"])])
        notes = {a["name"]: a["notes"] for a in added}
        self.assertIn("hasInstallScript", notes["@s/c"][0])
        self.assertIn("source outside the npm registry", notes["d"][0])

    def test_npm_lock_v1_nested(self):
        lock = d.p_npm_lock(json.dumps({"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}))
        self.assertEqual(lock.pkgs, {"a": {"1.0.0"}, "b": {"2.0.0"}})

    def test_cargo_skips_workspace_members_and_notes_git(self):
        lock = d.p_cargo(CARGO_NEW)
        self.assertEqual(set(lock.pkgs), {"serde", "evil"})
        self.assertIn("git source", lock.notes["evil"][0])

    def test_uv_skips_editable_and_normalizes_names(self):
        self.assertEqual(d.p_pylock(UV_NEW).pkgs, {"charset-normalizer": {"3.3.2"}})

    def test_requirements_only_pinned(self):
        self.assertEqual(d.p_requirements(REQ_NEW).pkgs, {"requests": {"2.32.0"}, "flask": {"3.0.0"}, "numpy": {"1.26.0"}})

    def test_go_sum_ignores_go_mod_lines(self):
        self.assertEqual(d.p_gosum(GOSUM_NEW).pkgs, {"github.com/a/b": {"v1.1.0"}, "github.com/c/d": {"v0.2.0"}})

    def test_composer_includes_dev(self):
        self.assertEqual(set(d.p_composer(COMPOSER_NEW).pkgs), {"monolog/monolog", "phpunit/phpunit"})

    def test_gemfile_specs_only(self):
        self.assertEqual(d.p_gemfile(GEM_NEW).pkgs, {"rack": {"2.2.0"}, "rails": {"7.0.0"}})

    def test_yarn_v1_scoped_names(self):
        self.assertEqual(d.p_yarn(YARN_NEW).pkgs, {"@babel/core": {"7.20.0"}, "lodash": {"4.17.21"}})

    def test_pnpm_best_effort(self):
        self.assertEqual(d.p_pnpm(PNPM_NEW).pkgs, {"@babel/core": {"7.20.0"}, "lodash": {"4.17.21"}})

    def test_pip_report(self):
        self.assertEqual(d.p_pip_report(PIP_REPORT).pkgs, {"requests": {"2.34.2"}, "charset-normalizer": {"3.5.2"}})
        with self.assertRaises(ValueError):
            d.p_pip_report("{}")

    def test_parser_selection_by_filename(self):
        self.assertIs(d.parser_for("x/package-lock.json"), d.p_npm_lock)
        self.assertIs(d.parser_for("Cargo.lock"), d.p_cargo)
        self.assertIs(d.parser_for("freeze.txt"), d.p_requirements)
        self.assertIsNone(d.parser_for("unknown.toml"))


class ParseOld(unittest.TestCase):
    def test_falls_back_to_old_file_parser(self):
        old = d.parse_old("requests==2.31.0\n", d.p_pip_report, d.p_requirements, "pypi")
        self.assertEqual(old.pkgs, {"requests": {"2.31.0"}})

    def test_empty_old_file_is_empty_lock(self):
        self.assertEqual(d.parse_old("", d.p_npm_lock, None, "npm").pkgs, {})


class Cli(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        p = subprocess.run([sys.executable, os.path.join(SCRIPTS, "diff_lock.py"), *args], capture_output=True, text=True, cwd=cwd)
        return p.returncode, json.loads(p.stdout)

    def test_two_files(self):
        with tempfile.TemporaryDirectory() as t:
            old, new = os.path.join(t, "old.json"), os.path.join(t, "package-lock.json")
            write(old, NPM_OLD)
            write(new, NPM_NEW)
            code, out = self.run_cli(old, new)
        self.assertEqual((code, out["summary"]), (0, {"added": 2, "removed": 1, "changed": 1}))

    def test_unsupported_lockfile_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "x.toml")
            write(f, "{}")
            code, out = self.run_cli(f, f)
        self.assertEqual((code, out["status"]), (2, "error"))

    @unittest.skipUnless(shutil.which("git"), "git not available")
    def test_git_mode_against_head(self):
        with tempfile.TemporaryDirectory() as t:
            def git(*a):
                subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=t, check=True, capture_output=True)
            git("init", "-q", ".")
            write(os.path.join(t, "package-lock.json"), NPM_OLD)
            git("add", "-A")
            git("commit", "-qm", "base")
            write(os.path.join(t, "package-lock.json"), NPM_NEW)
            code, out = self.run_cli("--git", "package-lock.json", cwd=t)
            self.assertEqual((code, out["summary"]["added"]), (0, 2))
            os.remove(os.path.join(t, "package-lock.json"))
            write(os.path.join(t, "other.lock"), "")
            git("rm", "-q", "--cached", "package-lock.json")
            git("commit", "-qm", "drop")
            write(os.path.join(t, "package-lock.json"), NPM_NEW)
            _, out = self.run_cli("--git", "package-lock.json", cwd=t)
            self.assertIn("not found at HEAD", out["note"])
            self.assertEqual(out["summary"]["added"], 3)


if __name__ == "__main__":
    unittest.main()
