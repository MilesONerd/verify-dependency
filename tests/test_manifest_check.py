# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Repository manifest cross-check: explicit states, so a missing comparison is never mistaken for a match."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402

API = {"full_name": "a/b", "stargazers_count": 50, "archived": False, "fork": False,
       "pushed_at": "2026-01-01T00:00:00Z", "created_at": "2020-01-01T00:00:00Z", "license": None}
INFO = {"repo": "https://github.com/a/b", "repo_dir": None}


def run(eco, raw=(200, '{"name": "pkg"}'), api_error=False):
    def fake(url, as_json=True, headers=None):
        if "api.github.com" in url:
            if api_error:
                raise c.NetErr("rate limited")
            return 200, API
        if "raw.githubusercontent.com" in url:
            return raw
        if url.startswith("https://github.com/"):
            return 200, "<html>"
        raise AssertionError(url)
    with mock.patch.object(c, "get", side_effect=fake):
        return c.gh_check(dict(INFO), eco, "pkg")


def flags(eco, gh):
    base = dict(version="1.0.0", created="2015-01-01T00:00:00", modified="2026-11-01T00:00:00", n_versions=40, repo=INFO["repo"],
                deprecated=None, install_scripts=None, adoption=("downloads", 10 ** 6, 1000), maintainers=["m"], notes=[])
    return {f["code"]: f["level"] for f in c.evaluate(eco, "pkg", base, gh)}


class ManifestCheck(unittest.TestCase):
    def test_npm_match(self):
        self.assertEqual(run("npm")["manifest_check"], "match")

    def test_npm_mismatch_is_a_medium_flag(self):
        gh = run("npm", raw=(200, '{"name": "other"}'))
        self.assertEqual(gh["manifest_check"], "mismatch")
        self.assertEqual(flags("npm", gh)["REPO_MANIFEST_MISMATCH"], "medium")

    def test_crates_toml_match(self):
        self.assertEqual(run("crates", raw=(200, '[package]\nname = "pkg"\n'))["manifest_check"], "match")

    def test_inconclusive_when_manifest_is_missing(self):
        gh = run("npm", raw=(404, None))
        self.assertEqual(gh["manifest_check"], "inconclusive")
        self.assertEqual(flags("npm", gh)["MANIFEST_NOT_CHECKED"], "info")

    def test_other_ecosystems_are_not_supported_and_say_so(self):
        for eco in ("gem", "nuget", "go", "packagist", "hex", "pub", "aur", "maven"):
            with self.subTest(eco=eco):
                gh = run(eco)
                self.assertEqual(gh["manifest_check"], "not_supported")
                self.assertIsNone(gh["manifest_name_matches"])
                self.assertEqual(flags(eco, gh)["MANIFEST_NOT_CHECKED"], "info")

    def test_state_is_kept_when_the_github_api_is_limited(self):
        gh = run("npm", api_error=True)
        self.assertEqual((gh["status"], gh["manifest_check"]), ("limited", "match"))


if __name__ == "__main__":
    unittest.main()
