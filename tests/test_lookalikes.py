# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Name-similarity signals: separators, look-alike characters, non-ASCII names, and no false positives on the real thing."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "verify-dependency", "scripts"))
import check_dep as c  # noqa: E402

BASE = dict(version="1.0.0", created="2015-01-01T00:00:00", modified="2026-11-01T00:00:00", n_versions=40, repo="https://github.com/a/b",
            deprecated=None, install_scripts=None, adoption=("downloads", 10 ** 6, 1000), maintainers=["m"], notes=[],
            release_times={"0.9.0": "2026-05-01T00:00:00", "1.0.0": "2026-11-01T00:00:00"})
GH = {"status": "ok", "stars": 100, "pushed_at": "2026-11-01T00:00:00"}


def similarity_codes(eco, name):
    wanted = {"SIMILAR_TO_POPULAR", "LOOKALIKE_OF_POPULAR", "NON_ASCII_NAME"}
    return {f["code"] for f in c.evaluate(eco, name, dict(BASE), GH) if f["code"] in wanted}


class Lookalikes(unittest.TestCase):
    def test_separator_swaps_are_flagged_on_npm_where_they_are_distinct_packages(self):
        for name in ("body_parser", "body.parser", "bodyparser"):
            with self.subTest(name=name):
                self.assertEqual(similarity_codes("npm", name), {"LOOKALIKE_OF_POPULAR"})

    def test_confusable_characters(self):
        for name in ("vvs", "rnoment", "l0dash", "axi0s"):
            with self.subTest(name=name):
                self.assertIn("LOOKALIKE_OF_POPULAR", similarity_codes("npm", name))

    def test_edit_distance_still_works(self):
        self.assertEqual(similarity_codes("npm", "lodahs"), {"SIMILAR_TO_POPULAR"})
        self.assertEqual(similarity_codes("npm", "expresss"), {"SIMILAR_TO_POPULAR"})

    def test_the_real_package_is_never_flagged(self):
        for eco, name in (("npm", "express"), ("npm", "body-parser"), ("npm", "ws"), ("pypi", "requests"), ("crates", "serde_json")):
            with self.subTest(name=name):
                self.assertEqual(similarity_codes(eco, name), set())

    def test_pypi_and_crates_normalize_names_so_variants_are_the_same_package(self):
        for eco, name in (("pypi", "python_dotenv"), ("pypi", "Flask"), ("pypi", "PyYAML"), ("crates", "serde-json")):
            with self.subTest(name=name):
                self.assertEqual(similarity_codes(eco, name), set())

    def test_non_ascii_name_is_flagged(self):
        self.assertIn("NON_ASCII_NAME", similarity_codes("npm", "\u0435xpress"))  # Cyrillic 'e'

    def test_unrelated_names_are_clean(self):
        self.assertEqual(similarity_codes("npm", "my-own-lib"), set())

    def test_flags_are_attention_not_strong_alerts(self):
        fl = {f["code"]: f["level"] for f in c.evaluate("npm", "body_parser", dict(BASE), GH)}
        self.assertEqual(fl["LOOKALIKE_OF_POPULAR"], "medium")


if __name__ == "__main__":
    unittest.main()
