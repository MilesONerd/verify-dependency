# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Dormant-package revival and publisher signals (the account-takeover patterns), the per-registry release data they rely on,
and the diff_lock check of new versions of packages that were already in the lockfile."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402
import diff_lock as d  # noqa: E402

GH = {"status": "ok", "stars": 100, "pushed_at": "2026-11-01T00:00:00"}


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


CONSISTENT = {"attestation_present": True, "provenance_consistent": True, "provenance_verified": False}


def info(rt, pubs=None, prov=None, version="2.0.0"):
    return dict(version=version, created=iso(4000), modified=iso(5), n_versions=len(rt or {}), repo="https://github.com/a/b",
                deprecated=None, install_scripts=None, adoption=("downloads", 10 ** 6, 1000), maintainers=["m"], notes=[],
                release_times=rt, publishers=pubs, provenance_check=prov)


def flags(i, **kw):
    return {f["code"]: f for f in c.evaluate("npm", "pkg", i, GH, **kw)}


class DormantRevival(unittest.TestCase):
    def test_flags_a_long_dormant_package_that_publishes_now(self):
        fl = flags(info({"1.0.0": iso(3000), "1.1.0": iso(2900), "2.0.0": iso(5)}))
        self.assertEqual(fl["RECENT_RELEASE_ON_MATURE_PKG"]["level"], "medium")

    def test_active_package_is_not_flagged(self):
        self.assertNotIn("RECENT_RELEASE_ON_MATURE_PKG", flags(info({"1.0.0": iso(200), "2.0.0": iso(5)})))

    def test_an_old_release_after_a_long_gap_is_not_flagged(self):
        self.assertNotIn("RECENT_RELEASE_ON_MATURE_PKG", flags(info({"1.0.0": iso(3000), "2.0.0": iso(100)})))

    def test_target_version_selects_which_release_is_judged(self):
        rt = {"1.0.0": iso(3000), "2.0.0": iso(5), "2.0.1": iso(2)}
        self.assertNotIn("RECENT_RELEASE_ON_MATURE_PKG", flags(info(rt, version="2.0.1")))
        self.assertIn("RECENT_RELEASE_ON_MATURE_PKG", flags(info(rt, version="2.0.1"), target_version="2.0.0"))

    def test_message_carries_the_publisher_context(self):
        rt = {"1.0.0": iso(3000), "2.0.0": iso(5)}
        known = flags(info(rt, {"1.0.0": "alice", "2.0.0": "alice"}))["RECENT_RELEASE_ON_MATURE_PKG"]["msg"]
        self.assertIn("who also published earlier releases", known)
        stranger = flags(info(rt, {"1.0.0": "alice", "2.0.0": "mallory"}, CONSISTENT))["RECENT_RELEASE_ON_MATURE_PKG"]["msg"]
        self.assertIn("who published none of the earlier releases", stranger)
        self.assertIn("with a build attestation consistent with the tarball", stranger)
        self.assertIn("signature not verified by this tool", stranger)

    def test_history_unavailable_is_stated_not_silently_clean(self):
        self.assertEqual(flags(info(None))["RELEASE_HISTORY_UNAVAILABLE"]["level"], "info")
        self.assertIn("RELEASE_HISTORY_UNAVAILABLE", flags(info({"1.0.0": iso(10)}), target_version="9.9.9"))


class NewPublisher(unittest.TestCase):
    RT = {"1.0.0": iso(300), "1.1.0": iso(200), "2.0.0": iso(20)}

    def test_unseen_publisher_without_provenance_is_flagged(self):
        fl = flags(info(self.RT, {"1.0.0": "alice", "1.1.0": "alice", "2.0.0": "mallory"}))
        self.assertEqual(fl["NEW_PUBLISHER"]["level"], "medium")

    def test_a_consistent_attestation_clears_it_trusted_publishing_is_not_a_takeover(self):
        fl = flags(info(self.RT, {"1.0.0": "alice", "1.1.0": "alice", "2.0.0": "GitHub Actions"}, CONSISTENT))
        self.assertNotIn("NEW_PUBLISHER", fl)
        self.assertEqual(fl["PROVENANCE_NOT_SIGNATURE_VERIFIED"]["level"], "info")

    def test_a_present_but_unchecked_or_inconsistent_attestation_does_not_clear_it(self):
        pubs = {"1.0.0": "alice", "1.1.0": "alice", "2.0.0": "mallory"}
        for pc in ({"attestation_present": True, "provenance_consistent": None, "issue": "could not be fetched"},
                   {"attestation_present": True, "provenance_consistent": False, "digest_matches": False, "issue": "digest"},
                   {"attestation_present": False}):
            with self.subTest(pc=pc):
                self.assertIn("NEW_PUBLISHER", flags(info(self.RT, pubs, pc)))

    def test_known_publisher_is_not_flagged(self):
        self.assertNotIn("NEW_PUBLISHER", flags(info(self.RT, {"1.0.0": "alice", "1.1.0": "bob", "2.0.0": "bob"})))

    def test_old_release_is_not_flagged(self):
        rt = {"1.0.0": iso(900), "1.1.0": iso(800), "2.0.0": iso(300)}
        self.assertNotIn("NEW_PUBLISHER", flags(info(rt, {"1.0.0": "alice", "1.1.0": "alice", "2.0.0": "mallory"})))


class RegistryData(unittest.TestCase):
    """Each registry that exposes per-version dates must produce them."""

    def run_case(self, fn, payloads):
        def fake(url, as_json=True, headers=None):
            for key, value in payloads.items():
                if key in url:
                    return 200, value
            raise c.NetErr("unavailable " + url)  # e.g. the npm downloads API: adoption is optional
        with mock.patch.object(c, "get", side_effect=fake):
            return fn()

    def test_npm_dates_publishers_and_provenance(self):
        doc = {"dist-tags": {"latest": "2.0.0"}, "time": {"created": "2015-01-01T00:00:00", "1.0.0": "2015-01-02T00:00:00", "2.0.0": "2026-01-01T00:00:00"},
               "versions": {"1.0.0": {"_npmUser": {"name": "alice"}, "dist": {}},
                            "2.0.0": {"_npmUser": {"name": "GitHub Actions"}, "dist": {"attestations": {"url": "x"}}}}, "maintainers": []}
        doc["versions"]["2.0.0"]["dist"]["integrity"] = "sha512-AAAA"
        doc["versions"]["2.0.0"]["dist"]["attestations"]["url"] = "https://registry.npmjs.org/-/npm/v1/attestations/pkg@2.0.0"
        got = self.run_case(lambda: c.r_npm("pkg"), {"registry.npmjs.org": doc})
        self.assertEqual(got["release_times"], {"1.0.0": "2015-01-02T00:00:00", "2.0.0": "2026-01-01T00:00:00"})
        self.assertEqual(got["publishers"], {"1.0.0": "alice", "2.0.0": "GitHub Actions"})
        self.assertEqual(got["attestation_urls"], {"1.0.0": None, "2.0.0": "https://registry.npmjs.org/-/npm/v1/attestations/pkg@2.0.0"})
        self.assertEqual(got["integrity"]["2.0.0"], "sha512-AAAA")

    def test_pypi_uses_the_earliest_upload_per_release(self):
        doc = {"info": {"version": "2.0"}, "releases": {"1.0": [{"upload_time": "2020-01-02T00:00:00"}, {"upload_time": "2020-01-01T00:00:00"}],
                                                       "2.0": [{"upload_time": "2024-05-05T00:00:00"}], "0.1": []}}
        got = self.run_case(lambda: c.r_pypi("pkg"), {"pypi.org": doc})
        self.assertEqual(got["release_times"], {"1.0": "2020-01-01T00:00:00", "2.0": "2024-05-05T00:00:00"})

    def test_crates_dates_and_publisher(self):
        doc = {"crate": {"max_version": "1.1.0", "created_at": "2020-01-01T00:00:00"},
               "versions": [{"num": "1.1.0", "created_at": "2024-01-01T00:00:00", "published_by": {"login": "dtolnay"}},
                            {"num": "1.0.0", "created_at": "2020-01-01T00:00:00", "published_by": None}]}
        got = self.run_case(lambda: c.r_crates("pkg"), {"crates.io": doc})
        self.assertEqual(got["release_times"], {"1.1.0": "2024-01-01T00:00:00", "1.0.0": "2020-01-01T00:00:00"})
        self.assertEqual(got["publishers"], {"1.1.0": "dtolnay", "1.0.0": None})

    def test_other_registries_expose_dates(self):
        cases = [
            (lambda: c.r_gem("g"), {"rubygems.org/api/v1/gems": {"version": "2.0"}, "rubygems.org/api/v1/versions": [
                {"number": "2.0", "created_at": "2024-01-01T00:00:00Z"}, {"number": "1.0", "created_at": "2020-01-01T00:00:00Z"}]},
             {"2.0": "2024-01-01T00:00:00Z", "1.0": "2020-01-01T00:00:00Z"}),
            (lambda: c.r_packagist("v/p"), {"packagist.org/packages": {"package": {"time": "2011-01-01T00:00:00+00:00", "versions": {
                "dev-main": {"time": "2026-01-01T00:00:00+00:00"}, "2.0": {"time": "2024-01-01T00:00:00+00:00"}, "1.0": {"time": "2020-01-01T00:00:00+00:00"}}}}},
             {"2.0": "2024-01-01T00:00:00+00:00", "1.0": "2020-01-01T00:00:00+00:00"}),
            (lambda: c.r_hex("h"), {"hex.pm": {"latest_version": "2.0", "releases": [{"version": "2.0", "inserted_at": "2024-01-01T00:00:00Z"},
                                                                                    {"version": "1.0", "inserted_at": "2020-01-01T00:00:00Z"}], "meta": {}}},
             {"2.0": "2024-01-01T00:00:00Z", "1.0": "2020-01-01T00:00:00Z"}),
            (lambda: c.r_pub("p"), {"pub.dev": {"latest": {"version": "2.0", "published": "2024-01-01T00:00:00Z", "pubspec": {}},
                                                "versions": [{"version": "2.0", "published": "2024-01-01T00:00:00Z"}, {"version": "1.0", "published": "2020-01-01T00:00:00Z"}]}},
             {"2.0": "2024-01-01T00:00:00Z", "1.0": "2020-01-01T00:00:00Z"}),
        ]
        for fn, payloads, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.run_case(fn, payloads)["release_times"], expected)

    def test_registries_without_per_version_dates_say_so(self):
        payloads = {"azuresearch": {"data": [{"id": "N", "version": "1", "totalDownloads": 1, "versions": [{}], "owners": []}]}}
        got = self.run_case(lambda: c.r_nuget("N"), payloads)
        self.assertIsNone(got["release_times"])


class CheckIntegration(unittest.TestCase):
    DOC = {"dist-tags": {"latest": "2.0.0"}, "time": {"created": iso(4000), "1.0.0": iso(3000), "2.0.0": iso(5)},
           "versions": {"1.0.0": {"_npmUser": {"name": "alice"}, "dist": {}}, "2.0.0": {"_npmUser": {"name": "mallory"}, "dist": {}}},
           "maintainers": [{"name": "alice"}], "repository": {"url": "git+https://github.com/a/b.git"}}

    def test_result_exposes_the_release_context_but_not_the_raw_maps(self):
        with mock.patch.object(c, "get", return_value=(200, self.DOC)):
            res, code = c.check("npm", "pkg", repo=False)
        reg = res["registry"]
        self.assertEqual((code, reg["target_version"], reg["target_publisher"]), (0, "2.0.0", "mallory"))
        self.assertFalse(reg["target_provenance"]["attestation_present"])
        self.assertFalse(reg["target_provenance"]["provenance_verified"])
        self.assertEqual(res["signals"], "attention")
        self.assertTrue({"RECENT_RELEASE_ON_MATURE_PKG", "NEW_PUBLISHER"} <= {f["code"] for f in res["flags"]})
        for k in ("release_times", "publishers", "attestation_urls", "integrity", "provenance_check"):
            self.assertNotIn(k, reg)

    def test_version_option_targets_another_release(self):
        with mock.patch.object(c, "get", return_value=(200, self.DOC)):
            res, _ = c.check("npm", "pkg", repo=False, version="1.0.0")
        self.assertEqual(res["registry"]["target_version"], "1.0.0")
        self.assertNotIn("RECENT_RELEASE_ON_MATURE_PKG", {f["code"] for f in res["flags"]})

    def test_version_option_without_value_is_an_error(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["check_dep.py", "npm", "pkg", "--version"]), contextlib.redirect_stdout(out),                 self.assertRaises(SystemExit) as cm:
            c.main()
        self.assertEqual(cm.exception.code, 2)


def fake_check(table):
    def check(eco, name, repo=True, version=None):
        status, codes, published = table[(name, version)]
        res = {"status": status, "flags": [{"code": x, "level": "medium"} for x in codes]}
        if status == "found":
            res["registry"] = {"target_published": published}
        else:
            res["error"] = "boom"
        return res, 0
    return check


class VerifyChanged(unittest.TestCase):
    def test_flags_and_dates_of_new_versions(self):
        changed = [{"name": "old-dep", "from": ["1.0.0"], "to": ["2.0.0"]}, {"name": "go-like", "from": ["1"], "to": ["2"]}]
        table = {("old-dep", "2.0.0"): ("found", ["RECENT_RELEASE_ON_MATURE_PKG", "SIMILAR_TO_POPULAR"], "2026-11-01"),
                 ("go-like", "2"): ("found", ["RELEASE_HISTORY_UNAVAILABLE"], None)}
        with mock.patch("check_dep.check", side_effect=fake_check(table)):
            d.verify_changed("npm", changed, {"checked": 0, "limit": 50})
        self.assertEqual(changed[0]["verification"]["flags"], ["RECENT_RELEASE_ON_MATURE_PKG"])  # only release-timing flags matter here
        self.assertEqual(changed[0]["verification"]["published"], {"2.0.0": "2026-11-01"})
        self.assertTrue(changed[0]["verification"]["release_dates_checked"])
        self.assertFalse(changed[1]["verification"]["release_dates_checked"])

    def test_only_versions_that_are_new_are_checked(self):
        changed = [{"name": "dep", "from": ["1.0.0"], "to": ["1.0.0", "2.0.0"]}]
        calls = []

        def spy(eco, name, repo=True, version=None):
            calls.append(version)
            return {"status": "found", "flags": [], "registry": {"target_published": "x"}}, 0
        with mock.patch("check_dep.check", side_effect=spy):
            d.verify_changed("npm", changed, {"checked": 0, "limit": 50})
        self.assertEqual(calls, ["2.0.0"])

    def test_budget_is_shared_and_exhaustion_is_reported(self):
        changed = [{"name": "a", "from": ["1"], "to": ["2"]}, {"name": "b", "from": ["1"], "to": ["2"]}]
        table = {("a", "2"): ("found", [], "2026-01-01"), ("b", "2"): ("found", [], "2026-01-01")}
        with mock.patch("check_dep.check", side_effect=fake_check(table)):
            d.verify_changed("npm", changed, {"checked": 0, "limit": 1})
        self.assertEqual(changed[1]["verification"]["status"], "skipped")

    def test_errors_are_reported_not_swallowed(self):
        changed = [{"name": "a", "from": ["1"], "to": ["2"]}]
        with mock.patch("check_dep.check", side_effect=fake_check({("a", "2"): ("error", [], None)})):
            d.verify_changed("npm", changed, {"checked": 0, "limit": 5})
        self.assertEqual(changed[0]["verification"]["status"], "error")

    def test_cli_lists_changed_packages_that_need_attention(self):
        lock = lambda v: json.dumps({"packages": {"": {}, "node_modules/dep": {"version": v}}})  # noqa: E731
        with tempfile.TemporaryDirectory() as t:
            old, new = os.path.join(t, "old.json"), os.path.join(t, "package-lock.json")
            for path, v in ((old, "1.0.0"), (new, "2.0.0")):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(lock(v))
            table = {("dep", "2.0.0"): ("found", ["NEW_PUBLISHER"], "2026-11-01")}
            out = io.StringIO()
            with mock.patch("check_dep.check", side_effect=fake_check(table)),                     mock.patch.object(sys, "argv", ["diff_lock.py", old, new, "--verify"]),                     contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
                d.main()
        res = json.loads(out.getvalue())
        self.assertEqual(res["changed_needs_attention"], ["dep"])
        self.assertEqual(res["changed_not_date_checked"], [])


class VerifyAdded(unittest.TestCase):
    """Added packages are judged by the version pinned in the lockfile, not by the registry's latest release."""

    def test_the_locked_version_is_the_one_checked(self):
        seen = []

        def spy(eco, name, repo=True, version=None):
            seen.append(version)
            return {"status": "found", "signals": "no_alerts", "flags": [], "registry": {"version": "9.9.9", "created": None, "maintainers": []}}, 0
        added = [{"name": "dep", "versions": ["1.2.3"], "notes": []}]
        with mock.patch("check_dep.check", side_effect=spy):
            d.verify("npm", added, 10)
        self.assertEqual(seen, ["1.2.3"])
        self.assertEqual(added[0]["verification"]["version"], "1.2.3")
        self.assertEqual(added[0]["verification"]["latest_in_registry"], "9.9.9")

    def test_several_locked_versions_are_all_checked_and_merged(self):
        def fake(eco, name, repo=True, version=None):
            flags = [{"code": "RECENT_RELEASE_ON_MATURE_PKG", "level": "medium"}] if version == "2.0.0" else []
            return {"status": "found", "signals": "attention" if flags else "no_alerts", "flags": flags,
                    "registry": {"version": "2.0.0", "created": None, "maintainers": []}}, 0
        added = [{"name": "dep", "versions": ["1.0.0", "2.0.0"], "notes": []}]
        with mock.patch("check_dep.check", side_effect=fake):
            d.verify("npm", added, 10)
        self.assertEqual(added[0]["verification"]["flags"], ["RECENT_RELEASE_ON_MATURE_PKG"])
        self.assertEqual(added[0]["verification"]["signals"], "attention")

    def test_a_missing_package_among_the_versions_is_reported(self):
        def fake(eco, name, repo=True, version=None):
            return {"status": "not_found", "flags": []}, 1
        added = [{"name": "ghost", "versions": ["1.0.0"], "notes": []}]
        with mock.patch("check_dep.check", side_effect=fake):
            d.verify("npm", added, 10)
        self.assertEqual((added[0]["verification"]["status"], added[0]["verification"]["flags"]), ("not_found", ["NOT_FOUND"]))


if __name__ == "__main__":
    unittest.main()
