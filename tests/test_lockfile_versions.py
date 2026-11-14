# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""pnpm and yarn lockfile format versions. A wrong parse is worse than an empty one, so each version is pinned here."""
import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
