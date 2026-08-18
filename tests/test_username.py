"""Tests for username.py's tool runners (graceful degradation, no network)."""

import unittest
from unittest import mock

from helpers import imp

uname = imp("username")


class RunnerGracefulTest(unittest.TestCase):
    def _run(self, fn):
        with mock.patch.object(uname, "_check_tool", return_value=True):
            return fn

    def test_sherlock_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("sherlock", 300)):
            self.assertEqual(uname._sherlock("johnsmith"), {})

    def test_maigret_error_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run", side_effect=OSError("boom")):
            self.assertEqual(uname._maigret("x"), {})

    def test_user_scanner_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("user-scanner", 120)):
            self.assertEqual(uname._us_username("x"), {})

    def test_blackbird_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("blackbird", 300)):
            self.assertEqual(uname._blackbird_username("x"), {})


if __name__ == "__main__":
    unittest.main()
