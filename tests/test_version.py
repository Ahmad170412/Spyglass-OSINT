"""Tests for version metadata and the ``--version`` CLI flag."""

import subprocess
import sys
import unittest

from helpers import _ROOT, imp

pkg = imp("")


class VersionTest(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(pkg.__version__, "1.1.0")

    def test_cli_version_flag(self):
        proc = subprocess.run(
            [sys.executable, "-m", "Spyglass-OSINT", "--version"],
            capture_output=True, text=True, cwd=_ROOT,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Spyglass 1.1.0", proc.stdout)

    def test_version_flag_wins_over_positionals(self):
        proc = subprocess.run(
            [sys.executable, "-m", "Spyglass-OSINT", "ip", "1.2.3.4", "--version"],
            capture_output=True, text=True, cwd=_ROOT,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Spyglass 1.1.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
