"""Guard against module filenames that shadow the standard library.

``email.py`` shipped in this package for a long time and broke any tool that
transitively imported the stdlib ``email`` module — Werkzeug does, through
``http.server``, which took the Flask console down with a bare ImportError.
The rename to ``email_recon.py`` fixed it; this test stops it coming back.
"""

import os
import sys
import unittest

from helpers import imp

# This directory, and the one containing it. Both are discovered rather than
# hardcoded so a renamed checkout does not silently skip the guard.
_PKG_DIR = os.path.dirname(os.path.abspath(imp("").__file__))
REPO_ROOT = os.path.dirname(_PKG_DIR)


class NoStdlibShadowingTest(unittest.TestCase):
    def test_no_module_filename_shadows_a_stdlib_module(self):
        std = set(sys.stdlib_module_names)
        offenders = []
        for name in os.listdir(REPO_ROOT):
            if not name.endswith(".py") or name == "__main__.py":
                continue
            if name[:-3] in std:
                offenders.append(name)
        self.assertEqual(offenders, [],
                         f"these filenames shadow stdlib modules: {offenders}")

    def test_email_recon_is_importable_and_reexports_email(self):
        mod = imp("email_recon")
        self.assertTrue(callable(mod.email))

    def test_stdlib_email_survives_the_package_directory_on_path(self):
        # The exact condition that broke Werkzeug: the package directory ahead
        # of the stdlib on sys.path must not shadow a stdlib module.
        pkg_dir = _PKG_DIR
        if not os.path.isdir(pkg_dir):
            self.skipTest("package directory not found")
        saved = list(sys.path)
        try:
            sys.path.insert(0, pkg_dir)
            for name in ("email", "email.utils", "email.parser"):
                sys.modules.pop(name, None)
            utils = __import__("email.utils", fromlist=["parsedate_tz"])
            self.assertTrue(hasattr(utils, "parsedate_tz"))
        finally:
            sys.path[:] = saved
            for name in ("email", "email.utils", "email.parser"):
                sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()
