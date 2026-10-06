"""Tests for version metadata and the ``--version`` CLI flag.

The expected version is read from the package rather than hardcoded. Three of
these assertions previously pinned "1.1.0" as a literal, so bumping
``__version__`` to 1.1.1 broke them without anything actually being wrong — the
tests were asserting a stale copy of a fact that already lived in one place.
"""

import os
import re
import subprocess
import sys
import unittest

from helpers import _ROOT, imp

pkg = imp("")

# The package directory is whatever the checkout was renamed to, which is not
# always "Spyglass-OSINT". ``helpers`` locates the parent; ask the package for
# its own name rather than assuming.
_PKG_NAME = pkg.__name__.split(".")[0]


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", _PKG_NAME, *args],
        capture_output=True, text=True, cwd=_ROOT,
    )


class VersionTest(unittest.TestCase):
    def test_package_version_is_a_dotted_release(self):
        self.assertRegex(pkg.__version__, r"^\d+\.\d+\.\d+")

    def test_cli_reports_the_package_version(self):
        proc = _run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(f"Spyglass {pkg.__version__}", proc.stdout)

    def test_version_flag_wins_over_positionals(self):
        proc = _run_cli("ip", "1.2.3.4", "--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(f"Spyglass {pkg.__version__}", proc.stdout)

    def test_version_flag_wins_over_a_module_name(self):
        # "version" is also a plausible module name; the flag must still win
        # rather than being treated as a positional target.
        proc = _run_cli("version", "--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(f"Spyglass {pkg.__version__}", proc.stdout)

    def test_changelog_documents_the_current_version(self):
        """A version bump without a changelog entry is how the 1.1.1 gap opened."""
        # _ROOT, not the package directory: CHANGELOG.md sits at the repository
        # root, and looking inside spyglass/ made this test skip on every run —
        # the guard silently guarding nothing.
        changelog = os.path.join(_ROOT, "CHANGELOG.md")
        if not os.path.isfile(changelog):
            self.skipTest("CHANGELOG.md not found")
        with open(changelog, encoding="utf-8") as fh:
            text = fh.read()
        released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", text, re.MULTILINE)
        self.assertTrue(released, "no released versions found in CHANGELOG.md")
        self.assertIn(
            pkg.__version__, released,
            f"__version__ is {pkg.__version__} but CHANGELOG.md only documents "
            f"{released}",
        )


if __name__ == "__main__":
    unittest.main()
