"""Tests for phone.py: phonenumbers validation, PhoneInfoga parsing, ignorant()."""

import unittest
from unittest import mock

from helpers import imp

phone = imp("phone")


class PhoneInfoTest(unittest.TestCase):
    def test_valid_singapore_number(self):
        info = phone._phonenumbers_info("+6585260980")
        self.assertNotIn("error", info)
        self.assertTrue(info["valid"])
        self.assertEqual(info["country_code"], 65)
        self.assertEqual(info["region"], "SG")
        self.assertEqual(info["e164"], "+6585260980")

    def test_invalid_input_reports_error(self):
        info = phone._phonenumbers_info("not a number")
        self.assertIn("error", info)


class IgnorantArgsTest(unittest.TestCase):
    def test_country_code_derived_correctly(self):
        # v1.0 fix: +65 8526 0980 must reach ignorant as cc=65 local=85260980,
        # not the old broken cc=658 local=585260980.
        captured = {}

        def fake_run(cmd, timeout=30):
            captured["cmd"] = cmd
            return ""

        with mock.patch.object(phone, "_IGNORANT", "/usr/bin/ignorant"), \
             mock.patch.object(phone, "_run", side_effect=fake_run):
            phone._ignorant("+6585260980")

        self.assertEqual(captured["cmd"], ["ignorant", "--only-used", "+65", "85260980"])

    def test_unparseable_number_falls_back_to_digit_split(self):
        captured = {}

        def fake_run(cmd, timeout=30):
            captured["cmd"] = cmd
            return ""

        with mock.patch.object(phone, "_IGNORANT", "/usr/bin/ignorant"), \
             mock.patch.object(phone, "_run", side_effect=fake_run):
            phone._ignorant("12345")

        self.assertEqual(captured["cmd"], ["ignorant", "--only-used", "+1", "2345"])


class PhoneInfogaTest(unittest.TestCase):
    """``_phoneinfoga`` called ``json.loads`` without importing ``json``.

    The resulting ``NameError`` was swallowed by the bare ``except`` around the
    parse, so the probe returned ``{}`` on every run and the engine silently
    contributed nothing. These tests pin the parse path, which is what the
    missing import broke.
    """

    def _run_with(self, stdout):
        with mock.patch.object(phone, "_PHONEINFOGA", "/usr/bin/phoneinfoga"), \
             mock.patch.object(phone, "_run", return_value=stdout):
            return phone._phoneinfoga("+6585260980")

    def test_json_output_is_parsed(self):
        out = self._run_with(
            '{"raw": "+6585260980", "e164": "+6585260980", '
            '"country": "Singapore", "osint": [{"url": "https://x.test/a"}]}'
        )
        self.assertEqual(out["e164"], "+6585260980")
        self.assertEqual(out["country"], "Singapore")
        self.assertEqual(out["sections"]["osint"], ["https://x.test/a"])

    def test_missing_binary_returns_empty(self):
        with mock.patch.object(phone, "_PHONEINFOGA", None), \
             mock.patch.object(phone, "_run") as runner:
            self.assertEqual(phone._phoneinfoga("+6585260980"), {})
        runner.assert_not_called()

    def test_empty_output_returns_empty(self):
        self.assertEqual(self._run_with(""), {})

    def test_malformed_json_returns_empty(self):
        self.assertEqual(self._run_with("not json at all"), {})

    def test_array_output_is_merged(self):
        out = self._run_with(
            '[{"e164": "+6585260980"}, {"country": "Singapore",'
            ' "osint": [{"url": "https://y.test/b"}]}]'
        )
        self.assertEqual(out["e164"], "+6585260980")
        self.assertEqual(out["country"], "Singapore")
        self.assertEqual(out["sections"]["osint"], ["https://y.test/b"])


if __name__ == "__main__":
    unittest.main()
