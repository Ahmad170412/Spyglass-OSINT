"""Tests for utils.py: domain parsing, entity extraction, safe filenames."""

import unittest

from helpers import imp

utils = imp("utils")


class DomainTest(unittest.TestCase):
    def test_www_stripped(self):
        self.assertEqual(utils._domain("https://www.example.com/x"), "example.com")

    def test_bare_domain(self):
        self.assertEqual(utils._domain("example.com"), "example.com")

    def test_port_and_query(self):
        self.assertEqual(
            utils._domain("http://sub.example.com:8080/path?q=1"),
            "sub.example.com",
        )


class ExtractIpsTest(unittest.TestCase):
    def test_ips_extracted_deduplicated(self):
        self.assertEqual(
            utils._extract_ips("host 1.2.3.4 and 5.6.7.8 and 1.2.3.4"),
            ["1.2.3.4", "5.6.7.8"],
        )


class ExtractEmailsTest(unittest.TestCase):
    def test_emails_extracted(self):
        self.assertEqual(
            utils._extract_emails("mail a@b.com then c.d@e.co.uk now"),
            ["a@b.com", "c.d@e.co.uk"],
        )


class ExtractPhonesTest(unittest.TestCase):
    def test_phones_extracted(self):
        out = utils._extract_phones("call +1 (555) 123-4567 or 202-555-0199 or 2025550199")
        self.assertIn("+1 (555) 123-4567", out)
        self.assertIn("202-555-0199", out)
        self.assertIn("2025550199", out)

    def test_dates_and_ips_rejected(self):
        self.assertEqual(utils._extract_phones("2024-01-01 at 1.2.3.4"), [])

    def test_registry_ids_not_phones(self):
        text = (
            "Registry Domain ID: 1264983250_DOMAIN_COM-VRSN\n"
            "Registrar IANA ID: 292\n"
            "Registrar Abuse Contact Phone: +1.2086851750\n"
        )
        out = utils._extract_phones(text)
        self.assertEqual(out, ["+1.2086851750"])


class ExtractWhoisFieldsTest(unittest.TestCase):
    def test_fields_parsed(self):
        text = (
            "Registrant Name: John Doe\n"
            "Registrant Email: j@x.com\n"
            "Organization: Acme\n"
            "ignored: line\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Registrant Name"], "John Doe")
        self.assertEqual(out["Registrant Email"], "j@x.com")
        self.assertEqual(out["Organization"], "Acme")

    def test_iana_thin_format(self):
        text = (
            "domain:       EXAMPLE.COM\n"
            "organisation: Internet Assigned Numbers Authority\n"
            "created:      1992-01-01\n"
            "source:       IANA\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Domain"], "EXAMPLE.COM")
        self.assertEqual(out["Organization"], "Internet Assigned Numbers Authority")
        self.assertEqual(out["Creation Date"], "1992-01-01")
        self.assertEqual(out["Source"], "IANA")

    def test_verisign_full_format(self):
        text = (
            "   Domain Name: GITHUB.COM\n"
            "   Registrar: MarkMonitor Inc.\n"
            "   Creation Date: 2007-10-09T18:20:50Z\n"
            "   Registry Expiry Date: 2026-10-09T18:20:50Z\n"
            "   DNSSEC: unsigned\n"
            "   Name Server: DNS1.P08.NSONE.NET\n"
            "   Name Server: DNS2.P08.NSONE.NET\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertEqual(out["Domain"], "GITHUB.COM")
        self.assertEqual(out["Registrar"], "MarkMonitor Inc.")
        self.assertEqual(out["Creation Date"], "2007-10-09T18:20:50Z")
        self.assertEqual(out["DNSSEC"], "unsigned")
        self.assertIn("DNS1.P08.NSONE.NET", out["Name Server"])
        self.assertIn("DNS2.P08.NSONE.NET", out["Name Server"])

    def test_repeatable_keys_joined(self):
        text = (
            "Domain Status: clientDeleteProhibited x\n"
            "Domain Status: clientTransferProhibited y\n"
        )
        out = utils._extract_whois_fields(text)
        self.assertIn("clientDeleteProhibited", out["Domain Status"])
        self.assertIn("clientTransferProhibited", out["Domain Status"])


class PickTest(unittest.TestCase):
    def test_first_dict_wins(self):
        pick = utils._pick({"a": 1}, {"a": 2, "b": 3})
        self.assertEqual(pick("a"), 1)
        self.assertEqual(pick("b"), 3)
        self.assertEqual(pick("z"), "z")


class SafeNameTest(unittest.TestCase):
    def test_sanitizes_hostile_characters(self):
        self.assertEqual(utils.safe_name("user@example.com/x:80"), "user_example.com_x_80")
        self.assertEqual(utils.safe_name("a b\tc"), "a_b_c")

    def test_empty_falls_back(self):
        self.assertEqual(utils.safe_name(""), "target")
        self.assertEqual(utils.safe_name("///"), "target")


if __name__ == "__main__":
    unittest.main()
