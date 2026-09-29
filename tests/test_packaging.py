"""Tests for the packaging itself.

These exist because the packaging was added late, and each assertion below
corresponds to a way the distribution can silently be wrong:

* A module left behind at the repository root is invisible to the wheel. The
  code still imports in a source tree — ``from .website import website`` resolves
  through the package, and ``python -m spyglass`` runs fine — so nothing fails
  until someone installs from a wheel and the module is simply gone. That is the
  failure the "no modules outside the package" test prevents.
* ``index.html`` is front-end code read with ``send_from_directory``. A wheel
  that omits it installs a console that 404s on its own page, and no unit test
  that calls a module function would ever notice.
* The console script has to name a real, public callable. A renamed or deleted
  ``main()`` produces an ``ImportError`` at first invocation, not at build time.
"""

import os
import unittest

from helpers import _ROOT, imp

pkg = imp("")
_PKG_DIR = os.path.dirname(os.path.abspath(pkg.__file__))


def _read(name):
    with open(os.path.join(_ROOT, name), encoding="utf-8") as fh:
        return fh.read()


class PackagingTest(unittest.TestCase):
    def test_no_module_files_are_stray_at_the_repository_root(self):
        # Everything importable belongs inside the package directory. A .py
        # file left at the root builds fine, imports fine from a checkout, and
        # is then missing from the installed distribution.
        strays = [n for n in os.listdir(_ROOT) if n.endswith(".py")]
        self.assertEqual(
            strays, [],
            f"these .py files are at the repository root, not in the package, "
            f"so they will not ship in the wheel: {strays}",
        )

    def test_every_package_module_is_inside_the_package_directory(self):
        # The mirror image of the test above, and the one that catches a file
        # that was never moved at all.
        self.assertTrue(os.path.isfile(os.path.join(_PKG_DIR, "__init__.py")))
        for name in ("__main__", "website", "asn", "store", "modules", "webapp"):
            self.assertTrue(
                os.path.isfile(os.path.join(_PKG_DIR, f"{name}.py")),
                f"spyglass/{name}.py is missing",
            )

    def test_the_console_script_target_exists_and_is_public(self):
        # pyproject points the `spyglass` command at spyglass.__main__:main.
        # main() is deliberately a public wrapper rather than the private
        # _cli(), so the entry point does not depend on a private name.
        main_mod = imp("__main__")
        self.assertTrue(callable(getattr(main_mod, "main", None)),
                        "spyglass.__main__:main is not callable — the console "
                        "script entry point would raise ImportError at runtime")

    def test_the_console_script_falls_back_to_a_runnable_path(self):
        # `python -m spyglass` is the documented no-install path, and it runs
        # __main__.py's own __main__ guard.
        self.assertIn('if __name__ == "__main__":',
                      _read_package_file("__main__.py"))

    def test_index_html_ships_as_package_data(self):
        # webapp.py serves it with send_from_directory(HERE, "index.html"), so
        # it must exist next to webapp.py *and* be declared, or the wheel
        # installs a console that 404s on its own front end.
        self.assertTrue(os.path.isfile(os.path.join(_PKG_DIR, "index.html")),
                        "index.html is not next to webapp.py")
        pyproject = _read("pyproject.toml")
        self.assertIn("[tool.setuptools.package-data]", pyproject)
        self.assertIn("index.html", pyproject.split("[tool.setuptools.package-data]")[1])

    def test_pyproject_declares_the_package_explicitly(self):
        # Auto-discovery refuses to choose between the spyglass/ and tests/
        # top-level directories, so an explicit list is required rather than
        # merely tidy. If it is ever dropped, the build fails loudly — which is
        # the correct outcome, but it should be caught here first.
        self.assertIn('packages = ["spyglass"]', _read("pyproject.toml"))

    def test_distribution_and_import_names_differ_deliberately(self):
        # `spyglass-osint` is the PyPI name; `spyglass` is the import package.
        # They are allowed to differ (pillow/PIL, beautifulsoup4/bs4) and here
        # they must: the PyPI name carries the -osint suffix the import name
        # does not need. Asserted so a rename of one is a conscious act.
        pyproject = _read("pyproject.toml")
        self.assertIn('name = "spyglass-osint"', pyproject)
        self.assertEqual(pkg.__name__.split(".")[0], "spyglass")

    def test_version_is_read_from_the_package_not_hardcoded(self):
        # Dynamic version keeps __init__.py the single source of truth, which
        # is what test_version.py's changelog check depends on.
        self.assertIn('version = { attr = "spyglass.__init__.__version__" }',
                      _read("pyproject.toml"))
        self.assertIn("[tool.setuptools.dynamic]", _read("pyproject.toml"))


def _read_package_file(name):
    with open(os.path.join(_PKG_DIR, name), encoding="utf-8") as fh:
        return fh.read()


if __name__ == "__main__":
    unittest.main()
