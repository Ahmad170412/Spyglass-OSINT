"""Tests for phone.py: phonenumbers validation and the ignorant() fix."""

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


if __name__ == "__main__":
    unittest.main()
