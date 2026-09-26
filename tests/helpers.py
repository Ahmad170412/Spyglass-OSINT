"""Shared import helper for the test suite.

The package directory name contains a dash, so a plain ``import <pkg>.email`` is
a syntax error. importlib handles the name fine, so every test imports through
``imp()``.

The package name is discovered from the filesystem rather than hardcoded. The
checkout has been renamed more than once — it has been ``TEMP`` and
``Spyglass-OSINT`` in the same session — and a hardcoded name turns every rename
into a silently empty test run (``Ran 0 tests``) rather than an obvious failure.

We also scrub ``sys.path``: if the tests are run from *inside* the package
directory, that directory lands on ``sys.path`` and its ``email_recon.py``
sits alongside the stdlib ``email`` import that urllib performs internally.
Importing strictly through the parent directory avoids the class of collision.
"""

import importlib
import os
import sys

# The package directory (the one holding __init__.py and utils.py).
_PKG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# The directory that *contains* it — the only place the package is importable by
# name, since ``python -m <pkg>`` and ``import <pkg>`` both resolve from here.
_ROOT = os.path.dirname(_PKG_DIR)

# Discover the real package name: it is the basename of the package directory.
_PKG = os.path.basename(_PKG_DIR)

if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Never leave the package directory itself on the path: its module filenames
# would shadow same-named standard-library modules.
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
