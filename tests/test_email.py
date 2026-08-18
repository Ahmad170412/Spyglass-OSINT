"""Tests for email.py's tool runners (graceful degradation, no network)."""

import unittest
from unittest import mock

from helpers import imp

em = imp("email")


class RunnerGracefulTest(unittest.TestCase):
    def test_holehe_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.subprocess, "run",
                               side_effect=em.subprocess.TimeoutExpired("holehe", 120)):
            self.assertEqual(em._holehe("x@example.com"), set())

    def test_us_email_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.subprocess, "run",
                               side_effect=em.subprocess.TimeoutExpired("user-scanner", 120)):
            self.assertEqual(em._us_email("x@example.com"), {})

    def test_blackbird_email_timeout_returns_empty(self):
        with mock.patch.object(em, "_check_tool", return_value=True), \
             mock.patch.object(em.subprocess, "run",
                               side_effect=em.subprocess.TimeoutExpired("blackbird", 120)):
            self.assertEqual(em._blackbird_email("x@example.com"), {})


if __name__ == "__main__":
    unittest.main()
