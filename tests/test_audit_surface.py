# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Machine-checkable audit surface of the skill itself.

A skill is part of your supply chain: SKILL.md is a persistent prompt and the scripts run on your machine.
These tests fail when the scripts start to contact a new host, import something unexpected, execute dynamic code,
write files, or run anything other than git. A change that trips one of them needs a deliberate review."""
import ast
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

SKILL = Path(__file__).resolve().parent.parent / "skills" / "verify-dependency"
SCRIPTS = sorted((SKILL / "scripts").glob("*.py"))
sys.path.insert(0, str(SKILL / "scripts"))
import check_dep as c  # noqa: E402

ALLOWED_HOSTS = {
    # package registries
    "registry.npmjs.org", "api.npmjs.org", "pypi.org", "pypistats.org", "crates.io", "rubygems.org",
    "azuresearch-usnc.nuget.org", "proxy.golang.org", "packagist.org", "aur.archlinux.org", "hex.pm", "pub.dev", "search.maven.org",
    # source forge used for the repository cross-check
    "api.github.com", "raw.githubusercontent.com", "github.com",
    # only shown to the user as links or compared with lockfile URLs, never fetched
    "www.npmjs.com", "www.nuget.org", "pkg.go.dev", "central.sonatype.com", "registry.yarnpkg.com",
}
ALLOWED_IMPORTS = {"sys", "json", "re", "os", "signal", "urllib", "datetime", "subprocess", "time", "check_dep"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("os", "remove"), ("os", "unlink"), ("os", "rmdir"), ("os", "rename"),
                   ("os", "chmod"), ("os", "makedirs"), ("os", "mkdir"), ("os", "execv"), ("os", "execvp")}


def trees():
    for p in SCRIPTS:
        yield p, ast.parse(p.read_text(encoding="utf-8"))


class AuditSurface(unittest.TestCase):
    def test_scripts_are_found(self):
        self.assertEqual({p.name for p in SCRIPTS}, {"check_dep.py", "diff_lock.py"})

    def test_only_allowlisted_hosts_appear_in_the_scripts(self):
        for p in SCRIPTS:
            hosts = {h for h in re.findall(r"https?://([A-Za-z0-9._{}-]+)", p.read_text(encoding="utf-8")) if "{" not in h}
            self.assertEqual(hosts - ALLOWED_HOSTS, set(), f"{p.name} mentions a host that is not in the audited allowlist")

    def test_only_allowlisted_imports(self):
        for p, tree in trees():
            mods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    mods.add((node.module or "").split(".")[0])
            self.assertEqual(mods - ALLOWED_IMPORTS, set(), p.name)

    def test_no_dynamic_code_execution_or_destructive_calls(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    if isinstance(f, ast.Name):
                        self.assertNotIn(f.id, FORBIDDEN_CALLS, f"{p.name}:{node.lineno}")
                    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                        self.assertNotIn((f.value.id, f.attr), FORBIDDEN_ATTRS, f"{p.name}:{node.lineno}")
                        self.assertNotEqual(f.value.id, "shutil", f"{p.name}:{node.lineno}")

    def test_the_only_subprocess_is_git(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call", "check_output") \
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    first = node.args[0]
                    self.assertIsInstance(first, ast.List, f"{p.name}:{node.lineno}")
                    self.assertEqual(getattr(first.elts[0], "value", None), "git", f"{p.name}:{node.lineno}")

    def test_scripts_never_open_files_for_writing(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                    mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                    if mode is not None:
                        self.assertIsInstance(mode, ast.Constant, f"{p.name}:{node.lineno}")
                        self.assertFalse(set("wax+") & set(mode.value), f"{p.name}:{node.lineno} opens a file for writing")

    def test_repository_urls_supplied_by_a_package_are_only_fetched_from_github(self):
        """A package controls its own metadata, so an attacker-chosen host must never be contacted."""
        for evil in ("https://evil.example.com/a/b", "http://169.254.169.254/latest/meta-data", "https://gitlab.com/a/b"):
            with self.subTest(url=evil), mock.patch.object(c, "get", side_effect=AssertionError("must not fetch " + evil)):
                out = c.gh_check({"repo": evil}, "npm", "pkg")
            self.assertEqual(out["status"], "unverified_host")

    def test_skill_md_does_not_tell_the_agent_to_hide_or_bypass(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8").lower()
        for phrase in ("ignore previous", "do not tell the user", "do not mention", "without asking", "disable the approval", "skip the approval"):
            self.assertNotIn(phrase, text, phrase)


if __name__ == "__main__":
    unittest.main()
