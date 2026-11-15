# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Machine-checkable audit surface of the skill itself.

A skill is part of your supply chain: SKILL.md is a persistent prompt and the scripts run on your machine.
Static analysis (this file) cannot prove safety, but it makes the common ways of going wrong fail loudly:
a new host, an unexpected import, dynamic code, any way of writing to disk, a redirect target, a subprocess other than git.
The runtime behavior (allowlisted hosts, refused redirects, requests chosen by package metadata) is tested in test_network_guard.py.
A change that trips one of these tests needs a deliberate review of the allowlists below."""
import ast
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

SKILL = Path(__file__).resolve().parent.parent / "skills" / "verify-dependency"
SCRIPTS = sorted((SKILL / "scripts").glob("*.py"))
sys.path.insert(0, str(SKILL / "scripts"))
import check_dep as c  # noqa: E402

# Hosts the scripts fetch from. Must equal check_dep.FETCH_HOSTS exactly.
FETCH_HOSTS = {
    "registry.npmjs.org", "api.npmjs.org", "pypi.org", "pypistats.org", "crates.io", "rubygems.org",
    "azuresearch-usnc.nuget.org", "proxy.golang.org", "packagist.org", "aur.archlinux.org", "hex.pm", "pub.dev", "search.maven.org",
    "api.github.com", "raw.githubusercontent.com", "github.com",
}
# Hosts that only appear as links shown to the user, or are compared with lockfile URLs. Never fetched.
DISPLAY_ONLY_HOSTS = {"www.npmjs.com", "www.nuget.org", "pkg.go.dev", "central.sonatype.com", "registry.yarnpkg.com"}
ALLOWED_IMPORTS = {"sys", "json", "re", "os", "signal", "urllib", "datetime", "subprocess", "time", "base64", "check_dep"}
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__", "breakpoint", "globals", "locals", "vars", "setattr", "delattr", "input"}
# Anything that can write, delete, rename or change files, spawn processes or change the environment.
FORBIDDEN_OS = {"system", "popen", "remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace", "chmod", "chown", "lchown", "fchmod",
                "makedirs", "mkdir", "mkfifo", "mknod", "symlink", "link", "truncate", "ftruncate", "utime", "open", "write", "writev", "fdopen",
                "execv", "execve", "execvp", "execl", "execle", "execlp", "spawnl", "spawnv", "fork", "kill", "killpg", "putenv", "unsetenv",
                "chdir", "chroot", "startfile"}
FORBIDDEN_ATTRS = {"urlretrieve", "urlcleanup", "urlopen", "install_opener", "URLopener", "FancyURLopener", "write_text", "write_bytes",
                   "__class__", "__subclasses__", "__globals__", "__builtins__", "__bases__", "__mro__", "__code__", "__dict__", "__getattribute__"}
ALLOWED_GIT_SUBCOMMANDS = {"rev-parse", "show"}


def trees():
    for p in SCRIPTS:
        yield p, ast.parse(p.read_text(encoding="utf-8"))


aliases = {}  # filled below, once alias_map is defined


def alias_map(tree):
    """Maps local names to what they refer to, so that `import os as _o`, `x = os` and `from os import replace` cannot hide a call."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, (ast.Name, ast.Attribute)):
            aliases[node.targets[0].id] = ".".join(attr_chain(node.value))
    return aliases


def resolved(node, aliases):
    chain = attr_chain(node)
    for _ in range(3):  # follow alias-of-alias
        if chain and chain[0] in aliases and aliases[chain[0]].split(".")[0] != chain[0]:
            chain = aliases[chain[0]].split(".") + chain[1:]
    return chain


def where(p, node):
    return f"{p.name}:{getattr(node, 'lineno', '?')}"


def attr_chain(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return list(reversed(parts))


aliases = {p: alias_map(t) for p, t in trees()}


class AuditSurface(unittest.TestCase):
    def test_scripts_are_found(self):
        self.assertEqual({p.name for p in SCRIPTS}, {"check_dep.py", "diff_lock.py"})

    def test_hosts_in_the_scripts_are_exactly_the_audited_lists(self):
        mentioned = set()
        for p in SCRIPTS:
            mentioned |= {h for h in re.findall(r"https?://([A-Za-z0-9._{}-]+)", p.read_text(encoding="utf-8")) if "{" not in h}
        self.assertEqual(mentioned - FETCH_HOSTS - DISPLAY_ONLY_HOSTS, set(), "a script mentions a host that is not audited")

    def test_the_runtime_allowlist_equals_the_audited_list(self):
        self.assertEqual(set(c.FETCH_HOSTS), FETCH_HOSTS)

    def test_from_imports_are_limited_to_datetime(self):
        """'from os import replace' or 'from subprocess import Popen' would bypass every attribute-based rule."""
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.module, "datetime", f"{where(p, node)}: from {node.module} import ...")

    def test_allowlist_constants_are_assigned_once_and_as_literals(self):
        """A later 'FETCH_HOSTS = FETCH_HOSTS | {...}', even in dead code or behind a condition, must not slip through."""
        for p, tree in trees():
            seen = {}
            for node in ast.walk(tree):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []
                for t in targets:
                    if isinstance(t, ast.Name) and t.id in {"FETCH_HOSTS", "ALLOWED_SCHEMES", "ALLOWED_PORTS", "_OPENER"}:
                        seen.setdefault(t.id, []).append(node)
            for name, nodes in seen.items():
                self.assertEqual(len(nodes), 1, f"{p.name}: {name} is assigned {len(nodes)} times")
                self.assertIsInstance(nodes[0], ast.Assign, f"{p.name}: {name} must be a plain assignment")
                if name != "_OPENER":
                    value = nodes[0].value
                    literal = isinstance(value, (ast.Tuple, ast.Constant)) or (isinstance(value, ast.Call) and getattr(value.func, "id", "") == "frozenset"
                                                                              and len(value.args) == 1 and isinstance(value.args[0], ast.Set))
                    self.assertTrue(literal, f"{p.name}: {name} must be a literal")

    def test_only_allowlisted_imports(self):
        for p, tree in trees():
            mods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    mods.add((node.module or "").split(".")[0])
            self.assertEqual(mods - ALLOWED_IMPORTS, set(), p.name)

    def test_no_dynamic_code_or_reflection_tricks(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    self.assertNotIn(node.id, FORBIDDEN_NAMES, where(p, node))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
                    ok = (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[0], ast.Name) and node.args[0].id == "sys")
                    self.assertTrue(ok, f"{where(p, node)}: getattr is only allowed as getattr(sys, '<constant>', ...)")

    def test_no_file_system_writes_process_control_or_downloads_to_disk(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, FORBIDDEN_ATTRS, where(p, node))
                    chain = resolved(node, aliases[p])
                    if chain[:1] == ["os"] and len(chain) == 2:
                        self.assertNotIn(chain[1], FORBIDDEN_OS, f"{where(p, node)}: os.{chain[1]}")
                    self.assertNotEqual(chain[:1], ["shutil"], where(p, node))
                    self.assertNotEqual(chain[:2], ["sys", "modules"], f"{where(p, node)}: sys.modules gives access to modules that were not imported")
                    self.assertFalse(chain[:2] == ["os", "environ"] and len(chain) > 2 and chain[2] in {"update", "setdefault", "pop", "popitem", "clear"},
                                     f"{where(p, node)}: modifies os.environ")

    def test_the_environment_is_never_assigned_or_deleted(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                    targets = [node.target]
                elif isinstance(node, ast.Delete):
                    targets = node.targets
                for t in targets:
                    if isinstance(t, ast.Subscript):
                        self.assertNotEqual(resolved(t.value, aliases[p])[:2], ["os", "environ"], where(p, node))

    def test_scripts_never_open_files_for_writing(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                    mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                    if mode is not None:
                        self.assertIsInstance(mode, ast.Constant, where(p, node))
                        self.assertFalse(set("wax+") & set(mode.value), f"{where(p, node)} opens a file for writing")

    def test_the_only_subprocess_is_git_and_only_read_only_subcommands(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                chain = resolved(node.func, aliases[p]) if isinstance(node.func, (ast.Attribute, ast.Name)) else []
                if chain[:1] == ["subprocess"]:
                    self.assertEqual(chain, ["subprocess", "run"], where(p, node))
                    first = node.args[0]
                    self.assertIsInstance(first, ast.List, where(p, node))
                    self.assertEqual(getattr(first.elts[0], "value", None), "git", where(p, node))
                if isinstance(node.func, ast.Name) and node.func.id == "_git":
                    arg = node.args[0]
                    self.assertIsInstance(arg, ast.List, where(p, node))
                    self.assertIn(getattr(arg.elts[0], "value", None), ALLOWED_GIT_SUBCOMMANDS, f"{where(p, node)}: git subcommand not allowed")

    def test_requests_go_through_the_guarded_opener_only(self):
        for p, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "open":
                    self.assertEqual(attr_chain(node.func), ["_OPENER", "open"], f"{where(p, node)}: use the guarded opener")

    def test_skill_md_does_not_tell_the_agent_to_hide_or_bypass(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8").lower()
        for phrase in ("ignore previous", "do not tell the user", "do not mention", "without asking", "disable the approval", "skip the approval"):
            self.assertNotIn(phrase, text, phrase)

    def test_repository_urls_supplied_by_a_package_are_only_fetched_from_github(self):
        for evil in ("https://evil.example.com/a/b", "http://169.254.169.254/latest/meta-data", "https://gitlab.com/a/b"):
            with self.subTest(url=evil), mock.patch.object(c, "get", side_effect=AssertionError("must not fetch " + evil)):
                out = c.gh_check({"repo": evil}, "npm", "pkg")
            self.assertEqual(out["status"], "unverified_host")


if __name__ == "__main__":
    unittest.main()
