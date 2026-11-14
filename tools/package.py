#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""Validates skills/verify-dependency and builds dist/verify-dependency.skill (a zip with one top-level folder)."""
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "verify-dependency"
OUT = ROOT / "dist" / "verify-dependency.skill"


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def validate():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not m:
        fail("SKILL.md has no frontmatter")
    fm = m.group(1)
    name = re.search(r"^name: (.+)$", fm, re.M)
    desc = re.search(r"^description: (.+)$", fm, re.M)
    lic = re.search(r"^license: (.+)$", fm, re.M)
    if not name or name.group(1).strip() != SKILL.name:
        fail("frontmatter name must equal the folder name")
    if not desc or len(desc.group(1)) > 1024 or ": " in desc.group(1):
        fail("description missing, longer than 1024 characters, or contains ': '")
    if not lic or lic.group(1).strip() != "Apache-2.0 OR MIT":
        fail("license must be 'Apache-2.0 OR MIT'")
    if not re.search(r"^metadata:\n(?:  .+\n)*?  author: .+$", fm + "\n", re.M):
        fail("metadata.author is missing")
    if len(text.splitlines()) > 500:
        fail("SKILL.md is longer than 500 lines")
    for lf in ("LICENSE-APACHE", "LICENSE-MIT"):
        if (ROOT / lf).read_bytes() != (SKILL / lf).read_bytes():
            fail(f"{lf} inside the skill differs from the root copy")
    for py in (SKILL / "scripts").glob("*.py"):
        if "SPDX-License-Identifier: Apache-2.0 OR MIT" not in py.read_text(encoding="utf-8")[:300]:
            fail(f"{py.name} is missing the SPDX header")


def build():
    OUT.parent.mkdir(exist_ok=True)
    files = sorted(p for p in SKILL.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, Path(SKILL.name) / p.relative_to(SKILL))
    print(f"built {OUT.relative_to(ROOT)} ({len(files)} files)")


if __name__ == "__main__":
    validate()
    build()
