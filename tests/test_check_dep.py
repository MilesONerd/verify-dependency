# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Offline tests for check_dep.py. Registry calls are mocked; live tests are opt-in (VERIFY_DEP_LIVE=1)."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def info(**kw):
    base = dict(version="1.0.0", created=iso(2000), modified=iso(10), n_versions=40, repo="https://github.com/a/b",
                deprecated=None, install_scripts=None, adoption=("weekly downloads (npm)", 10 ** 6, 1000), maintainers=["m"], notes=[])
    base.update(kw)
    return base


def codes(flags):
    return {f["code"] for f in flags}


def levels(flags):
    return {f["code"]: f["level"] for f in flags}


class Helpers(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(c.lev("lodahs", "lodash"), 2)
        self.assertEqual(c.lev("express", "express"), 0)

    def test_norm(self):
        self.assertEqual(c.norm("Charset_Normalizer"), "charset-normalizer")

    def test_parse_repo_variants(self):
        for url in ("git+https://github.com/a/b.git", "git@github.com:a/b.git", "github:a/b", "a/b",
                    "https://github.com/a/b/tree/main/x", "git://github.com/a/b.git"):
            self.assertEqual(c.parse_repo(url), ("github.com", "a", "b"), url)
        self.assertIsNone(c.parse_repo("not a url"))

    def test_stdlib_names(self):
        self.assertIn("path", c.stdlib_names("npm"))
        self.assertIn("os", c.stdlib_names("pypi"))
        self.assertNotIn("express", c.stdlib_names("npm"))
        self.assertEqual(c.stdlib_names("crates"), set())


class Evaluate(unittest.TestCase):
    def ev(self, eco="npm", name="somepkg", gh=None, **kw):
        return c.evaluate(eco, name, info(**kw), gh or {"status": "ok", "stars": 500, "pushed_at": iso(5)})

    def test_clean_package_has_no_flags(self):
        self.assertEqual(self.ev(), [])

    def test_new_package_is_medium(self):
        self.assertEqual(levels(self.ev(created=iso(5)))["NEW_PACKAGE"], "medium")

    def test_stale_is_maintenance_not_medium(self):
        fl = self.ev(modified=iso(3000))
        self.assertEqual(levels(fl)["STALE"], "maintenance")
        self.assertNotIn("medium", levels(fl).values())

    def test_few_versions_and_deprecated_are_maintenance(self):
        fl = levels(self.ev(n_versions=1, deprecated="use other"))
        self.assertEqual(fl["FEW_VERSIONS"], "maintenance")
        self.assertEqual(fl["DEPRECATED"], "maintenance")

    def test_security_holding_is_high(self):
        self.assertEqual(levels(self.ev(version="0.0.1-security"))["SECURITY_HOLDING"], "high")

    def test_repo_not_found_is_high(self):
        fl = self.ev(gh={"status": "not_found", "url": "https://github.com/a/b"})
        self.assertEqual(levels(fl)["REPO_NOT_FOUND"], "high")

    def test_no_repo_is_medium(self):
        self.assertEqual(levels(self.ev(repo=None, gh={"status": "no_repo"}))["NO_REPO"], "medium")

    def test_install_scripts_flagged(self):
        self.assertIn("INSTALL_SCRIPTS", codes(self.ev(install_scripts=["postinstall"])))

    def test_low_adoption(self):
        self.assertIn("LOW_ADOPTION", codes(self.ev(adoption=("weekly downloads (npm)", 12, 1000))))

    def test_adoption_unavailable_is_info_for_npm(self):
        self.assertEqual(levels(self.ev(adoption=None))["ADOPTION_UNAVAILABLE"], "info")

    def test_stdlib_name_collision(self):
        self.assertEqual(levels(self.ev(name="path"))["STDLIB_NAME_COLLISION"], "medium")
        self.assertEqual(levels(self.ev(eco="pypi", name="os"))["STDLIB_NAME_COLLISION"], "medium")

    def test_typosquat_of_popular_package(self):
        self.assertIn("SIMILAR_TO_POPULAR", codes(self.ev(name="lodahs")))
        self.assertNotIn("SIMILAR_TO_POPULAR", codes(self.ev(name="lodash")))

    def test_manifest_mismatch(self):
        gh = {"status": "ok", "stars": 500, "pushed_at": iso(5), "manifest_name_matches": False}
        self.assertIn("REPO_MANIFEST_MISMATCH", codes(self.ev(gh=gh)))

    def test_repo_fork_archived_inactive(self):
        gh = {"status": "ok", "stars": 500, "pushed_at": iso(3000), "is_fork": True, "archived": True}
        fl = levels(self.ev(gh=gh))
        self.assertEqual(fl["REPO_IS_FORK"], "medium")
        self.assertEqual(fl["REPO_ARCHIVED"], "maintenance")
        self.assertEqual(fl["REPO_INACTIVE"], "maintenance")

    def test_limited_github_is_info_not_alert(self):
        fl = levels(self.ev(gh={"status": "limited", "note": "rate limited"}))
        self.assertEqual(fl["REPO_UNVERIFIED"], "info")

    def test_aur_orphan(self):
        self.assertIn("ORPHAN", codes(self.ev(eco="aur", maintainers=[])))


class Check(unittest.TestCase):
    def test_not_found(self):
        with mock.patch.object(c, "get", return_value=(404, None)):
            res, code = c.check("npm", "express-zz-fake", repo=False)
        self.assertEqual((res["status"], res["signals"], code), ("not_found", "strong_alerts", 1))

    def test_network_error_is_never_not_found_nor_clean(self):
        with mock.patch.object(c, "get", side_effect=c.NetErr("blocked")):
            res, code = c.check("pypi", "requests", repo=False)
        self.assertEqual((res["status"], code), ("error", 2))
        self.assertNotIn("signals", res)

    def test_no_repo_option_skips_github(self):
        doc = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"license": "MIT"}},
               "time": {"created": iso(2000), "modified": iso(10)}, "maintainers": [{"name": "m"}],
               "repository": {"url": "git+https://github.com/a/b.git"}}
        with mock.patch.object(c, "get", return_value=(200, doc)), \
                mock.patch.object(c, "gh_check", side_effect=AssertionError("must not be called")):
            res, code = c.check("npm", "somepkg", repo=False)
        self.assertEqual(code, 0)
        self.assertEqual(res["repository"]["status"], "skipped")

    def test_signals_ignore_maintenance_flags(self):
        doc = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}, "time": {"created": iso(4000), "modified": iso(3000)},
               "maintainers": [{"name": "m"}], "repository": {"url": "git+https://github.com/a/b.git"}}
        with mock.patch.object(c, "get", return_value=(200, doc)):
            res, _ = c.check("npm", "somepkg", repo=False)
        self.assertIn("STALE", codes(res["flags"]))
        self.assertEqual(res["signals"], "no_alerts")

    def test_unknown_ecosystem_via_cli(self):
        with mock.patch.object(sys, "argv", ["check_dep.py", "foo", "bar"]), self.assertRaises(SystemExit) as cm:
            c.main()
        self.assertEqual(cm.exception.code, 2)


class RegistryParsers(unittest.TestCase):
    """Parsers for registries that cannot be reached from every environment, checked against mocked payloads."""
    DATA = {
        "rubygems.org/api/v1/gems": {"version": "7.1.0", "downloads": 10 ** 9, "source_code_uri": "https://github.com/rails/rails",
                                     "licenses": ["MIT"], "info": "x", "authors": "DHH"},
        "rubygems.org/api/v1/versions": [{"created_at": "2023-10-05T10:00:00Z"}],
        "azuresearch": {"data": [{"id": "Newtonsoft.Json", "version": "13", "totalDownloads": 9, "verified": True,
                                  "projectUrl": "https://github.com/a/b", "owners": ["x"], "versions": [{}], "description": "x"}]},
        "proxy.golang.org/github.com/a/b/@latest": {"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"},
        "proxy.golang.org/github.com/a/b/@v/list": "v1.0.0\n",
        "packagist.org/packages": {"package": {"name": "m/m", "time": "2011-01-01T00:00:00+00:00",
                                               "repository": "https://github.com/a/b", "downloads": {"total": 9},
                                               "versions": {"1.0": {"license": ["MIT"]}}, "maintainers": [{"name": "s"}], "description": "x"}},
        "aur.archlinux.org": {"resultcount": 1, "results": [{"Version": "1", "Maintainer": None, "NumVotes": 3, "FirstSubmitted": 1700000000,
                                                             "LastModified": 1700000000, "URL": "https://github.com/a/b",
                                                             "License": ["GPL3"], "Description": "x", "OutOfDate": 1}]},
        "hex.pm": {"latest_version": "1.0", "inserted_at": "2014-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z", "releases": [{}],
                   "meta": {"links": {"GitHub": "https://github.com/x/y"}, "licenses": ["MIT"], "description": "d"},
                   "downloads": {"all": 1}, "owners": [{"username": "a"}]},
        "pub.dev": {"latest": {"version": "1.0", "published": "2024-01-01T00:00:00Z", "pubspec": {"repository": "https://github.com/a/b"}},
                    "versions": [{"published": "2020-01-01T00:00:00Z"}], "isDiscontinued": True},
        "search.maven.org": {"response": {"numFound": 1, "docs": [{"latestVersion": "3", "versionCount": 2, "timestamp": 1700000000000}]}},
    }

    def fake_get(self, url, as_json=True, headers=None):
        for key, value in self.DATA.items():
            if key in url:
                return 200, value
        raise AssertionError("no mock for " + url)

    def run_case(self, eco, name):
        with mock.patch.object(c, "get", side_effect=self.fake_get):
            return c.REGISTRIES[eco](name)

    def test_all_registries_parse(self):
        cases = [("gem", "rails", "7.1.0"), ("nuget", "Newtonsoft.Json", "13"), ("go", "github.com/a/b", "v1.0.0"),
                 ("packagist", "m/m", "1.0"), ("aur", "yay", "1"), ("hex", "phx", "1.0"), ("pub", "http", "1.0"),
                 ("maven", "g:a", "3")]
        for eco, name, version in cases:
            with self.subTest(eco=eco):
                got = self.run_case(eco, name)
                self.assertEqual(got["version"], version)
                c.evaluate(eco, name, got, {"status": "unverified_host"})  # must not raise

    def test_aur_orphan_and_out_of_date(self):
        got = self.run_case("aur", "yay")
        self.assertEqual(got["maintainers"], [])
        self.assertTrue(got["deprecated"])

    def test_maven_requires_group_and_artifact(self):
        with self.assertRaises(c.NetErr):
            c.r_maven("only-artifact")


@unittest.skipUnless(os.environ.get("VERIFY_DEP_LIVE"), "set VERIFY_DEP_LIVE=1 to run live registry tests")
class Live(unittest.TestCase):
    def test_known_and_invented_packages(self):
        res, code = c.check("npm", "express", repo=False)
        self.assertEqual((res["status"], code), ("found", 0))
        res, code = c.check("npm", "express-super-validator-zq9", repo=False)
        self.assertEqual((res["status"], code), ("not_found", 1))
        res, _ = c.check("pypi", "requests", repo=False)
        self.assertEqual(res["status"], "found")


if __name__ == "__main__":
    unittest.main()
