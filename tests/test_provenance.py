# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""npm build attestations: present, consistent and verified are three different things, and only the middle one can be checked here."""
import base64
import hashlib
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402

URL = "https://registry.npmjs.org/-/npm/v1/attestations/pkg@2.0.0"
DIGEST = hashlib.sha512(b"the published tarball").hexdigest()
INTEGRITY = "sha512-" + base64.b64encode(bytes.fromhex(DIGEST)).decode()
SLSA = "https://slsa.dev/provenance/v1"


def attestation(subject="pkg:npm/pkg@2.0.0", digest=DIGEST, repo="https://github.com/a/b", predicate=SLSA, payload=None):
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": subject, "digest": {"sha512": digest}}], "predicateType": predicate,
                 "predicate": {"buildDefinition": {"externalParameters": {"workflow": {"repository": repo, "ref": "refs/tags/v2.0.0", "path": ".github/workflows/r.yml"}}}}}
    body = payload if payload is not None else base64.b64encode(json.dumps(statement).encode()).decode()
    return {"attestations": [{"predicateType": predicate, "bundle": {"dsseEnvelope": {"payload": body, "signatures": [{"sig": "x"}]}}}]}


def info(**kw):
    base = {"attestation_urls": {"2.0.0": URL}, "integrity": {"2.0.0": INTEGRITY}, "repo": "git+https://github.com/a/b.git"}
    base.update(kw)
    return base


def check(doc, **kw):
    with mock.patch.object(c, "get", return_value=(200, doc) if not isinstance(doc, tuple) else doc):
        return c.provenance_check(info(**kw), "2.0.0")


class Levels(unittest.TestCase):
    def test_consistent_attestation_is_still_never_verified(self):
        out = check(attestation())
        self.assertEqual((out["attestation_present"], out["provenance_consistent"], out["provenance_verified"]), (True, True, False))
        self.assertEqual((out["digest_matches"], out["repository_matches"]), (True, True))
        self.assertEqual(out["workflow_repository"], "https://github.com/a/b")

    def test_provenance_verified_is_false_in_every_outcome(self):
        outcomes = [check(attestation()), check(attestation(digest="0" * 128)), check(attestation(repo="https://github.com/x/y")),
                    check(attestation(payload="not-base64!!")), check((404, None)), c.provenance_check({"attestation_urls": {}}, "2.0.0")]
        self.assertTrue(all(o["provenance_verified"] is False for o in outcomes))

    def test_no_attestation_means_no_request(self):
        with mock.patch.object(c, "get", side_effect=AssertionError("must not fetch")):
            out = c.provenance_check({"attestation_urls": {"2.0.0": None}}, "2.0.0")
        self.assertEqual((out["attestation_present"], out["provenance_consistent"]), (False, None))


class Mismatches(unittest.TestCase):
    def test_digest_of_another_tarball(self):
        out = check(attestation(digest=hashlib.sha512(b"something else").hexdigest()))
        self.assertEqual((out["digest_matches"], out["provenance_consistent"]), (False, False))
        self.assertIn("digest", out["issue"])

    def test_statement_about_another_version(self):
        out = check(attestation(subject="pkg:npm/pkg@1.0.0"))
        self.assertEqual((out["digest_matches"], out["provenance_consistent"]), (False, False))

    def test_scoped_package_subject_names(self):
        self.assertTrue(check(attestation(subject="pkg:npm/%40s/pkg@2.0.0"))["provenance_consistent"])

    def test_source_repository_differs_from_the_declared_one(self):
        out = check(attestation(repo="https://github.com/evil/fork"))
        self.assertEqual((out["repository_matches"], out["provenance_consistent"], out["digest_matches"]), (False, False, True))

    def test_repository_comparison_ignores_case_and_git_suffix(self):
        self.assertTrue(check(attestation(repo="https://github.com/A/B.git"))["provenance_consistent"])

    def test_malformed_payload_is_inconsistent_not_a_crash(self):
        for bad in ("not-base64!!", base64.b64encode(b"[1, 2]").decode(), base64.b64encode(b"{}").decode()):
            with self.subTest(payload=bad[:12]):
                out = check(attestation(payload=bad))
                self.assertIs(out["provenance_consistent"] is True, False)

    def test_bundle_without_a_provenance_statement(self):
        out = check(attestation(predicate="https://github.com/npm/attestation/tree/main/specs/publish/v0.1"))
        self.assertEqual(out["provenance_consistent"], False)
        self.assertIn("no SLSA provenance", out["issue"])


class CouldNotBeChecked(unittest.TestCase):
    def test_fetch_failure_is_unknown_not_consistent(self):
        with mock.patch.object(c, "get", side_effect=c.NetErr("boom")):
            out = c.provenance_check(info(), "2.0.0")
        self.assertEqual((out["attestation_present"], out["provenance_consistent"]), (True, None))
        self.assertIn("could not be fetched", out["issue"])

    def test_missing_attestation_document_is_unknown(self):
        self.assertIsNone(check((404, None))["provenance_consistent"])

    def test_unknown_tarball_digest_is_unknown(self):
        out = check(attestation(), integrity={})
        self.assertIsNone(out["provenance_consistent"])
        self.assertIn("could not be compared", out["issue"])

    def test_an_attestation_url_outside_the_registry_is_refused_without_a_request(self):
        with mock.patch.object(c, "get", side_effect=AssertionError("must not fetch")):
            out = c.provenance_check(info(attestation_urls={"2.0.0": "https://evil.example.com/-/npm/v1/attestations/x"}), "2.0.0")
        self.assertEqual(out["provenance_consistent"], False)
        self.assertIn("unexpected attestation URL", out["issue"])


class Flags(unittest.TestCase):
    def flags(self, pc):
        base = dict(version="2.0.0", created="2015-01-01T00:00:00", modified="2026-11-01T00:00:00", n_versions=5, repo="https://github.com/a/b",
                    deprecated=None, install_scripts=None, adoption=("d", 10 ** 6, 1000), maintainers=["m"], notes=[],
                    release_times={"1.0.0": "2026-05-01T00:00:00", "2.0.0": "2026-11-01T00:00:00"}, provenance_check=pc)
        return {f["code"]: f["level"] for f in c.evaluate("npm", "pkg", base, {"status": "ok", "stars": 9, "pushed_at": "2026-11-01T00:00:00"})}

    def test_digest_mismatch_is_a_strong_alert(self):
        self.assertEqual(self.flags({"attestation_present": True, "provenance_consistent": False, "digest_matches": False})["PROVENANCE_DIGEST_MISMATCH"], "high")

    def test_repository_mismatch_needs_attention(self):
        fl = self.flags({"attestation_present": True, "provenance_consistent": False, "repository_matches": False, "workflow_repository": "https://github.com/x/y"})
        self.assertEqual(fl["PROVENANCE_REPO_MISMATCH"], "medium")

    def test_consistent_attestation_still_says_the_signature_was_not_verified(self):
        self.assertEqual(self.flags({"attestation_present": True, "provenance_consistent": True})["PROVENANCE_NOT_SIGNATURE_VERIFIED"], "info")

    def test_unchecked_attestation_is_stated(self):
        self.assertEqual(self.flags({"attestation_present": True, "provenance_consistent": None, "issue": "x"})["PROVENANCE_UNCHECKED"], "info")

    def test_no_attestation_adds_no_provenance_flag(self):
        self.assertFalse([k for k in self.flags({"attestation_present": False}) if k.startswith("PROVENANCE")])


if __name__ == "__main__":
    unittest.main()
