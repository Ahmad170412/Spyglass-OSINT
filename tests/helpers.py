"""Shared import helper for the test suite.

Spyglass is now a properly-named package (``spyglass/``) with a real
distribution on PyPI, so the importlib indirection this file used to need is
mostly historical. It is kept because two things still depend on it:

* ``tests/`` is deliberately *not* part of the installed distribution, so the
  suite has to put the repository root on ``sys.path`` itself rather than
  relying on being run from an installed copy.
* The package directory is discovered from the filesystem rather than
  hardcoded, so a renamed checkout does not turn every test into a silent
  ``Ran 0 tests``.

The name also has to be *valid* now, not merely importable by importlib. The
checkout used to be ``Spyglass-OSINT``, which a plain ``import`` statement
cannot even name.
"""

import importlib
import os
import sys

# The repository root: the directory holding pyproject.toml.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The package directory (the one holding __init__.py and utils.py).
_PKG_DIR = os.path.join(_ROOT, "spyglass")

# Discover the real package name: it is the basename of the package directory.
_PKG = os.path.basename(_PKG_DIR)

if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Never leave the package directory itself on the path. Its module filenames
# are plain names — ``phone``, ``report``, ``store`` — and several of them
# shadow real modules other packages import. ``email_recon`` exists for exactly
# this reason; the guard below stops the next one being an accident.
sys.path[:] = [
    p for p in sys.path
    if p != "" and os.path.abspath(p) != _PKG_DIR
]


def imp(name: str = ""):
    """Import a module inside the Spyglass package by short name.

    ``imp()`` returns the package itself; ``imp("cve")`` returns its ``cve``
    submodule. The package name is read from the filesystem, so renaming the
    checkout does not break the suite.
    """
    module = _PKG if not name else f"{_PKG}.{name}"
    return importlib.import_module(module)
