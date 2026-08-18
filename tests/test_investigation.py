"""Tests for investigation.py: entity collection, correlation, input parsing.

The heavy module functions (email, username, website, ...) shell out to
external tools, so only the pure logic is tested here with crafted results.
"""

import unittest
from unittest import mock

from helpers import imp

inv = imp("investigation")


def _entities():
    return {
        "emails": set(), "domains": set(), "ips": set(),
        "orgs": set(), "asns": set(), "phones": set(),
    }


class CollectEntitiesTest(unittest.TestCase):
    def test_website_whois_entities(self):
        results = {
            "website": {
                "dns_records": {"A": "1.2.3.4, 5.6.7.8"},
                "whois": {
                    "Organization": "Acme Inc",
                    "Registrant Email": "a@acme.com, b@acme.com",
                    "Phone": "+1 555 0100",
                },
            },
            "email": {},
        }
        entities = _entities()
        inv._collect_entities(results, entities)
        self.assertIn("1.2.3.4", entities["ips"])
        self.assertIn("5.6.7.8", entities["ips"])
        self.assertIn("Acme Inc", entities["orgs"])
        self.assertIn("a@acme.com", entities["emails"])
        self.assertIn("b@acme.com", entities["emails"])
        self.assertIn("acme.com", entities["domains"])
        self.assertIn("+1 555 0100", entities["phones"])

    def test_phone_region_collected(self):
        results = {"phone": {"phonenumbers": {"region": "Singapore"}}}
        entities = _entities()
        inv._collect_entities(results, entities)
        self.assertEqual(entities["regions"], {"Singapore"})


class CorrelateTest(unittest.TestCase):
    def test_email_domain_matches_website(self):
        inputs = {"email": "a@x.com", "website": "x.com"}
        corr = inv._correlate(inputs, {"email": {}, "website": {}}, {"domains": {"x.com"}})
        self.assertTrue(
            any(c["type"] == "match" and "matches website" in c["desc"] for c in corr)
        )

    def test_phone_region_matches_whois_country(self):
        # phonenumbers reports the ISO region code ("SG"), matching WHOIS country.
        inputs = {"phone": "+65 8526 0980"}
        results = {
            "phone": {"phonenumbers": {"region": "SG"}},
            "website": {"whois": {"Country": "SG"}},
        }
        corr = inv._correlate(inputs, results, _entities())
        self.assertTrue(
            any(c["type"] == "match" and "Phone region matches" in c["desc"] for c in corr)
        )

    def test_username_total_counted(self):
        inputs = {"username": "jdoe"}
        results = {"username": {"all_4": [{"domain": "a.com"}, {"domain": "b.com"}]}}
        corr = inv._correlate(inputs, results, _entities())
        self.assertTrue(any("Username found on 2 platforms" in c["desc"] for c in corr))


class InvestigateTest(unittest.TestCase):
    def test_runs_modules_and_collects_entities(self):
        email_mod = imp("email")
        username_mod = imp("username")
        phone_mod = imp("phone")
        website_mod = imp("website")
        with mock.patch.object(inv, "_quick_resolve", return_value=None), \
             mock.patch.object(email_mod, "email",
                               return_value={"both": [], "holehe_only": [],
                                             "user_scanner_only": [], "blackbird_only": [],
                                             "breach": {"found": 0}}) as em, \
             mock.patch.object(username_mod, "username",
                               return_value={"all_4": [{"domain": "gh.com"}],
                                             "breach": {"found": 0}}) as um, \
             mock.patch.object(phone_mod, "phone",
                               return_value={"phonenumbers": {"error": "no tools"}}) as pm, \
             mock.patch.object(website_mod, "website",
                               return_value={"dns_records": {"A": "1.2.3.4"},
                                             "whois": {"Organization": "Acme"}}) as wm:
            r = inv.investigate({"email": "a@x.com", "username": "jdoe",
                                 "phone": "+15550000", "website": "x.com"})

        em.assert_called_once_with("a@x.com")
        um.assert_called_once_with("jdoe")
        pm.assert_called_once_with("+15550000")
        wm.assert_called_once_with("x.com")
        self.assertIn("email", r["results"])
        self.assertIn("username", r["results"])
        self.assertIn("website", r["results"])
        # Input-derived entities survive even when the phone module errored.
        self.assertIn("x.com", r["entities"]["domains"])
        self.assertIn("a@x.com", r["entities"]["emails"])

    def test_missing_modules_are_skipped(self):
        email_mod = imp("email")
        username_mod = imp("username")
        with mock.patch.object(inv, "_quick_resolve", return_value=None), \
             mock.patch.object(email_mod, "email",
                               return_value={"both": [], "breach": {"found": 0}}), \
             mock.patch.object(username_mod, "username",
                               return_value={"all_4": [], "breach": {"found": 0}}):
            r = inv.investigate({"username": "onlyme"})
        self.assertNotIn("email", r["results"])
        self.assertIn("username", r["results"])


class ParseInputTest(unittest.TestCase):
    def test_key_value_format(self):
        main = imp("__main__")
        self.assertEqual(
            main._parse_investigation_input("email: a@x.com, username: jdoe"),
            {"email": "a@x.com", "username": "jdoe"},
        )

    def test_positional_format(self):
        main = imp("__main__")
        self.assertEqual(
            main._parse_investigation_input("a@x.com, jdoe, +6585260980, example.com"),
            {"email": "a@x.com", "username": "jdoe",
             "phone": "+6585260980", "website": "example.com"},
        )

    def test_blank_input(self):
        main = imp("__main__")
        self.assertEqual(main._parse_investigation_input("  , , "), {})


if __name__ == "__main__":
    unittest.main()
