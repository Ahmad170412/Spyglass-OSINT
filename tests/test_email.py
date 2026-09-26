"""Tests for email.py's tool runners (graceful degradation, no network)."""

import unittest
from unittest import mock

from helpers import imp

em = imp("email_recon")
utils_mod = imp("utils")


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


class GravatarHashTest(unittest.TestCase):
    def test_hash_is_md5_of_the_trimmed_lowercased_address(self):
        # Gravatar's spec: md5 of the address lowercased and trimmed. Getting
        # this wrong silently returns "no profile" for a real one.
        import hashlib
        expected = hashlib.md5(b"test@example.com").hexdigest()
        self.assertEqual(em._gravatar_hash("test@example.com"), expected)
        self.assertEqual(em._gravatar_hash("  Test@Example.COM  "), expected)

    def test_rejects_non_addresses(self):
        for bad in ("", "notanemail", "  ", "@", "a@"):
            self.assertEqual(em._gravatar_hash(bad), "")


class GravatarLookupTest(unittest.TestCase):
    """The network call is stubbed; only the decision logic is exercised."""

    def test_no_avatar_reports_not_found_without_fetching_the_profile(self):
        with mock.patch.object(em, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(utils_mod, "_curl_status", return_value=404), \
             mock.patch.object(em, "_gravatar_json") as gj:
            out = em._gravatar("test@example.com")
        self.assertEqual(out["status"], "ok")
        self.assertFalse(out["found"])
        gj.assert_not_called()

    def test_invalid_address_is_an_error(self):
        out = em._gravatar("nope")
        self.assertEqual(out["status"], "error")
        self.assertFalse(out["found"])

    def test_missing_curl_is_unavailable_not_a_crash(self):
        with mock.patch.object(em, "_CURL", None):
            out = em._gravatar("test@example.com")
        self.assertEqual(out["status"], "unavailable")

    def test_avatar_present_fetches_the_profile(self):
        payload = {"entry": [{
            "hash": "abc", "profileUrl": "https://gravatar.com/abc",
            "displayName": "Jane Doe", "preferredUsername": "jdoe",
            "currentLocation": "Berlin", "aboutMe": "hello",
            "photos": [{"type": "thumbnail"}],
            "accounts": [
                {"shortname": "jdoe", "domain": "twitter.com",
                 "username": "jdoe", "url": "https://twitter.com/jdoe"},
                {"shortname": "", "domain": "", "username": "", "url": ""},
            ],
        }]}
        with mock.patch.object(em, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(utils_mod, "_curl_status", return_value=200), \
             mock.patch.object(em, "_gravatar_json", return_value=payload):
            out = em._gravatar("test@example.com")
        self.assertTrue(out["found"])
        self.assertEqual(out["display_name"], "Jane Doe")
        self.assertEqual(out["username"], "jdoe")
        self.assertEqual(out["location"], "Berlin")
        self.assertEqual(out["photos"], 1)
        # The empty account entry must be dropped, not rendered as a blank row.
        self.assertEqual(len(out["accounts"]), 1)
        self.assertEqual(out["accounts"][0]["service"], "twitter")
        self.assertEqual(out["accounts"][0]["url"], "https://twitter.com/jdoe")

    def test_avatar_present_but_profile_withheld(self):
        with mock.patch.object(em, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(utils_mod, "_curl_status", return_value=200), \
             mock.patch.object(em, "_gravatar_json", return_value={}):
            out = em._gravatar("test@example.com")
        self.assertTrue(out["found"])
        self.assertIn("note", out)


if __name__ == "__main__":
    unittest.main()
