"""Shared import helper for the test suite.

The package directory is named ``Spyglass-OSINT`` (with a dash), so a plain
``import Spyglass-OSINT.email`` is a syntax error. importlib handles the name
fine, so every test imports through ``imp()``.

We also scrub ``sys.path``: if the tests are run from *inside* the package
directory, that directory lands on ``sys.path`` and its ``email.py`` module
shadows Python's stdlib ``email`` package (used internally by urllib), which
breaks imports. Always importing the package via its parent directory avoids
the collision.
"""

import importlib
import os
import sys

# Workspace root — the directory that *contains* the Spyglass-OSINT package.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# The package directory itself (never import it as a flat directory).
_PKG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path[:] = [
    p for p in sys.path
    if p != "" and os.path.abspath(p) != _PKG_DIR
]


def imp(name: str):
    """Import a module inside the Spyglass-OSINT package by short name."""
    module = "Spyglass-OSINT" if not name else f"Spyglass-OSINT.{name}"
    return importlib.import_module(module)
