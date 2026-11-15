# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""pnpm and yarn lockfile format versions. A wrong parse is worse than an empty one, so each version is pinned here."""
import os
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import diff_lock as d  # noqa: E402

EXPECTED = {"@babel/core": {"7.20.0"}, "react-dom": {"18.2.0"}}

PNPM_V5 = ("lockfileVersion: 5.4\npackages:\n  /@babel/core/7.20.0:\n    resolution: {integrity: x}\n"
           "  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: z}\n  /lodash/4.17.21:\n    resolution: {integrity: y}\n")
PNPM_V6 = ("lockfileVersion: '6.0'\npackages:\n  /@babel/core@7.20.0:\n    resolution: {integrity: x}\n"
           "  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: z}\n")
PNPM_V9 = ("lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.20.0':\n    resolution: {integrity: x}\n"
           "  react-dom@18.2.0:\n    resolution: {integrity: z}\nsnapshots:\n  react-dom@18.2.0(react@18.2.0): {}\n  extra@1.0.0: {}\n")
BERRY = ('__metadata:\n  version: 6\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n\n'
         '"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n'
         '"typescript@patch:typescript@npm%3A^5.0.0#~builtin<compat/typescript>::version=5.0.4&hash=abc":\n  version: 5.0.4\n\n'
         '"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":\n  version: 1.1.0\n')
V1 = '# yarn lockfile v1\n\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.20.0"\n\nlodash@^4.17.0:\n  version "4.17.21"\n'


class Pnpm(unittest.TestCase):
    def test_v5_strips_peer_suffix_and_keeps_scoped_names(self):
        self.assertEqual(d.p_pnpm(PNPM_V5).pkgs, {**EXPECTED, "lodash": {"4.17.21"}})

    def test_v6_strips_peer_suffix_in_parentheses(self):
        self.assertEqual(d.p_pnpm(PNPM_V6).pkgs, EXPECTED)

    def test_v9_ignores_snapshots_section(self):
        self.assertEqual(d.p_pnpm(PNPM_V9).pkgs, EXPECTED)

    def test_no_garbage_names(self):
        for text in (PNPM_V5, PNPM_V6, PNPM_V9):
            for name in d.p_pnpm(text).pkgs:
                self.assertNotIn("_", name)
                self.assertNotIn("(", name)


class Yarn(unittest.TestCase):
    def test_berry_skips_workspaces_and_fixes_patch_names(self):
        self.assertEqual(d.p_yarn(BERRY).pkgs, {"lodash": {"4.17.21"}, "typescript": {"5.0.4"}, "@scope/pkg": {"1.1.0"}})

    def test_v1_scoped_names(self):
        self.assertEqual(d.p_yarn(V1).pkgs, {"@babel/core": {"7.20.0"}, "lodash": {"4.17.21"}})


GO_LIST = "example.com/demo\ngithub.com/hashicorp/errwrap v1.0.0\ngithub.com/hashicorp/go-multierror v1.1.1\n"


class GoList(unittest.TestCase):
    def test_go_list_output_is_parsed_and_the_main_module_is_skipped(self):
        self.assertEqual(d.p_golist(GO_LIST).pkgs, {"github.com/hashicorp/errwrap": {"v1.0.0"}, "github.com/hashicorp/go-multierror": {"v1.1.1"}})

    def test_file_name_selects_the_go_parser_before_the_generic_txt_rule(self):
        self.assertIs(d.parser_for("go-list-new.txt"), d.p_golist)
        self.assertIs(d.parser_for("go.sum"), d.p_gosum)
        self.assertIs(d.parser_for("requirements.txt"), d.p_requirements)

    def test_diff_of_two_graphs(self):
        added, _, _ = d.diff(d.p_golist("example.com/demo\n"), d.p_golist(GO_LIST))
        self.assertEqual({a["name"] for a in added}, {"github.com/hashicorp/errwrap", "github.com/hashicorp/go-multierror"})


class GoReplace(unittest.TestCase):
    """Real `go list -m all` output (Go 1.22) with replace directives. The replacement is what gets built."""

    def test_local_directory_replacement_is_not_a_registry_package(self):
        for right in ("./local-errwrap", "../x", "/abs/path/x", "C:\\work\\x"):
            with self.subTest(right=right):
                lock = d.p_golist(f"example.com/demo\ngithub.com/hashicorp/errwrap v1.0.0 => {right}\ngithub.com/a/b v1.0.0\n")
                self.assertEqual(set(lock.pkgs), {"github.com/a/b"})
                self.assertEqual(lock.local, {"github.com/hashicorp/errwrap": right})

    def test_remote_replacement_records_the_version_really_used(self):
        lock = d.p_golist("example.com/demo\ngithub.com/hashicorp/errwrap v1.0.0 => github.com/hashicorp/errwrap v1.1.0\n")
        self.assertEqual(lock.pkgs, {"github.com/hashicorp/errwrap": {"v1.1.0"}})
        self.assertIn("replaces github.com/hashicorp/errwrap v1.0.0", lock.notes["github.com/hashicorp/errwrap"][0])

    def test_replacement_by_a_different_module_path(self):
        lock = d.p_golist("example.com/demo\ngithub.com/old/mod v1.0.0 => github.com/fork/mod v1.0.1-fixed\n")
        self.assertEqual(lock.pkgs, {"github.com/fork/mod": {"v1.0.1-fixed"}})
        self.assertEqual(lock.local, {})

    def test_cli_reports_new_local_replacements_instead_of_verifying_them(self):
        import contextlib, io, json, tempfile
        with tempfile.TemporaryDirectory() as t:
            old, new = os.path.join(t, "go-list-old.txt"), os.path.join(t, "go-list-new.txt")
            for path, text in ((old, "example.com/demo\ngithub.com/a/b v1.0.0\n"), (new, "example.com/demo\ngithub.com/a/b v1.0.0 => ./b\n")):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            out = io.StringIO()
            with unittest.mock.patch.object(sys, "argv", ["diff_lock.py", old, new]), contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
                d.main()
        res = json.loads(out.getvalue())
        self.assertEqual(res["local_replacements"]["added"], ["github.com/a/b => ./b"])
        self.assertEqual(res["added"], [])


if __name__ == "__main__":
    unittest.main()
