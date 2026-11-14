# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Keeps the documentation honest: commands and paths shown in the docs must exist and be runnable as written."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "verify-dependency"


def read(p):
    return Path(p).read_text(encoding="utf-8")


class Docs(unittest.TestCase):
    def test_root_doc_commands_exist_from_repo_root(self):
        for doc in ("AGENTS.md", "README.md"):
            for path in re.findall(r"python3 (?!-m)([\w./-]+\.py)", read(ROOT / doc)):
                with self.subTest(doc=doc, path=path):
                    self.assertTrue((ROOT / path).is_file(), f"{doc}: {path} does not exist from the repo root")

    def test_no_bare_script_paths_in_root_docs(self):
        for doc in ("AGENTS.md", "README.md"):
            bare = re.findall(r"(?<![\w/.<>-])scripts/[\w.-]+\.py", read(ROOT / doc))
            self.assertEqual(bare, [], f"{doc} mentions scripts without the full path: {bare}")

    def test_skill_md_uses_skill_dir_placeholder(self):
        text = read(SKILL / "SKILL.md")
        blocks = "\n".join(re.findall(r"```[a-z]*\n(.*?)```", text, re.S))  # what an agent would copy and run
        bad = [line for line in blocks.splitlines() if "python3 scripts/" in line]
        self.assertEqual(bad, [], "runnable commands must use <skill-dir>/scripts/...")
        used = set(re.findall(r"<skill-dir>/(scripts/[\w.-]+\.py)", text))
        self.assertTrue(used)
        for rel in used:
            self.assertTrue((SKILL / rel).is_file(), rel)

    def test_relative_links_in_readme_exist(self):
        for link in re.findall(r"\]\((?!https?://|#)([^)\s]+)\)", read(ROOT / "README.md")):
            self.assertTrue((ROOT / link).exists(), link)

    def test_agent_files_point_to_agents_md(self):
        self.assertIn("@AGENTS.md", read(ROOT / "CLAUDE.md").splitlines())
        self.assertIn("@./AGENTS.md", read(ROOT / "GEMINI.md").splitlines())
        self.assertIn("read: AGENTS.md", read(ROOT / ".aider.conf.yml").splitlines())
        self.assertIn("AGENTS.md", read(ROOT / ".github" / "copilot-instructions.md"))

    def test_files_that_would_shadow_agents_md_in_zed_are_absent(self):
        for name in (".rules", ".cursorrules", ".windsurfrules", ".clinerules"):
            self.assertFalse((ROOT / name).exists(), name)

    def test_repository_url_is_consistent(self):
        m = re.search(r"^  repository: (\S+)$", read(SKILL / "SKILL.md"), re.M)
        self.assertTrue(m)
        self.assertIn(m.group(1), read(ROOT / "README.md"))
        self.assertIn(m.group(1), read(ROOT / "AGENTS.md"))


if __name__ == "__main__":
    unittest.main()
