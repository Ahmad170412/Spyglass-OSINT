"""Guard against module filenames that shadow the standard library.

``email.py`` shipped in this package for a long time and broke any tool that
transitively imported the stdlib ``email`` module — Werkzeug does, through
``http.server``, which took the Flask console down with a bare ImportError.
The rename to ``email_recon.py`` fixed it; this test stops it coming back.

The hazard did not go away when the checkout was renamed. Every module is now
a real module of an installed distribution, so ``spyglass/phone.py`` is a
top-level import named ``phone`` for anything doing ``from spyglass import *``,
and one day ``spyglass/report.py`` or ``spyglass/store.py`` will be a stdlib
module too. The guard matters more now, not less.
"""

import os
import sys
import unittest

from helpers import imp

# The package directory itself — this is where the module filenames live, and
# the only place the guard is meaningful.
#
# It used to scan ``os.path.dirname(_PKG_DIR)`` instead, which was the parent of
# the checkout and has never contained a .py file. The assertion therefore held
# over an empty list and would have passed with ``email.py`` sitting right next
# to it. A guard that cannot fail is not a guard; the fix is to scan the real
# directory, and the test below pins that the scan is not empty.
_PKG_DIR = os.path.dirname(os.path.abspath(imp("").__file__))


class NoStdlibShadowingTest(unittest.TestCase):
    def _module_filenames(self):
        return sorted(
            name for name in os.listdir(_PKG_DIR)
            if name.endswith(".py") and name != "__main__.py"
        )

    def test_the_guard_is_scanning_a_directory_that_has_modules(self):
        # If this fails, the guard is pointed at the wrong directory again and
        # the assertion below is passing vacuously.
        self.assertGreater(
            len(self._module_filenames()), 10,
            f"expected the package's modules in {_PKG_DIR}, found none — the "
            f"shadowing guard is scanning the wrong directory",
        )

    def test_no_module_filename_shadows_a_stdlib_module(self):
        std = set(sys.stdlib_module_names)
        offenders = [name for name in self._module_filenames()
                     if name[:-3] in std]
        self.assertEqual(offenders, [],
                         f"these filenames shadow stdlib modules: {offenders}")

    def test_email_recon_is_importable_and_reexports_email(self):
        mod = imp("email_recon")
        self.assertTrue(callable(mod.email))

    def test_stdlib_email_survives_the_package_directory_on_path(self):
        # The exact condition that broke Werkzeug: the package directory ahead
        # of the stdlib on sys.path must not shadow a stdlib module.
        if not os.path.isdir(_PKG_DIR):
            self.skipTest("package directory not found")
        saved = list(sys.path)
        try:
            sys.path.insert(0, _PKG_DIR)
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
