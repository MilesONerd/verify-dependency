# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""The packaged skill must be byte-for-byte reproducible, otherwise its published SHA-256 cannot be verified by anyone."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build_in_copy():
    with tempfile.TemporaryDirectory() as t:
        copy = Path(t) / "copy"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("dist", "__pycache__", ".git"))
        for f in copy.rglob("*"):  # different modification times on purpose
            if f.is_file():
                os.utime(f, (time.time() - 12345, time.time() - 12345))
        subprocess.run([sys.executable, str(copy / "tools" / "package.py")], check=True, capture_output=True)
        return hashlib.sha256((copy / "dist" / "verify-dependency.skill").read_bytes()).hexdigest()


class Reproducible(unittest.TestCase):
    def test_two_builds_with_different_file_times_give_the_same_hash(self):
        first = build_in_copy()
        time.sleep(1.1)
        self.assertEqual(first, build_in_copy())


if __name__ == "__main__":
    unittest.main()
