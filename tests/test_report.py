"""Tests for report.py: Markdown dossier rendering and writing."""

import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

report = imp("report")


class RenderEmailTest(unittest.TestCase):
    def test_email_dossier(self):
        r = {
            "both": [{"domain": "example.com", "url": "https://example.com"}],
            "holehe_only": [{"domain": "foo.net"}],
            "user_scanner_only": [],
            "blackbird_only": [],
            "breach": {
                "found": 2,
                "sources": [{"name": "LeakDB", "date": "2021"}, {"name": "Other"}],
                "fields": ["email", "name"],
            },
        }
        md = report.render(r, "email", "user@example.com")
        self.assertIn("# Spyglass Report — email", md)
        self.assertIn("**Target:** `user@example.com`", md)
        self.assertIn("example.com", md)
        self.assertIn("foo.net", md)
        self.assertIn("**Breach found:** 2", md)
        self.assertIn("LeakDB (2021)", md)
        self.assertIn("**Exposed fields:** email, name", md)


class RenderIpTest(unittest.TestCase):
    def test_ip_dossier(self):
        r = {
            "ip": "1.2.3.4",
            "geo": {"country": "US", "city": "Testville", "isp": "Test ISP"},
            "open_ports": [22, 443],
        }
        md = report.render(r, "ip", "1.2.3.4")
        self.assertIn("### Geolocation", md)
        self.assertIn("**Country:** US", md)
        self.assertIn("### Open ports (nmap)", md)
        self.assertIn("- 22", md)
        self.assertIn("- 443", md)


class RenderErrorTest(unittest.TestCase):
    def test_error_result_rendered_as_quote(self):
        md = report.render({"error": "Could not resolve: nope.invalid"}, "ip", "nope.invalid")
        self.assertIn("Could not resolve: nope.invalid", md)


class RenderInvestigationTest(unittest.TestCase):
    def test_correlations_and_entities(self):
        r = {
            "inputs": {"email": "a@x.com"},
            "entities": {"domains": ["x.com"], "ips": ["1.2.3.4"]},
            "correlations": [
                {"type": "match", "desc": "Email domain matches website target", "detail": "x.com"}
            ],
            "results": {},
        }
        md = report.render(r, "investigation", "a@x.com")
        self.assertIn("### Known inputs", md)
        self.assertIn("### Entities found", md)
        self.assertIn("**Domains:** x.com", md)
        self.assertIn("### Correlations", md)
        self.assertIn("MATCH", md)


class RenderOpsecTest(unittest.TestCase):
    def test_recommendations_rendered(self):
        r = {
            "proxy_configured": True,
            "dns_leak": "unverified",
            "recommendations": ["DNS may leak — install torsocks to route DNS through Tor"],
        }
        md = report.render(r, "opsec", "")
        self.assertIn("### Recommendations", md)
        self.assertIn("DNS may leak", md)


class WriteReportTest(unittest.TestCase):
    def test_write_report_creates_sanitized_file(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(report._ui, "info"):
            path = report.write_report({"a": 1}, "ip", "1.2.3.4:80", tmp)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(os.path.basename(path).startswith("spyglass_report_ip_1.2.3.4_80_"))
            with open(path) as f:
                self.assertIn("# Spyglass Report — ip", f.read())

    def test_render_reports_version(self):
        pkg = imp("")
        self.assertIn(f"- **Spyglass version:** {pkg.__version__}", report.render({}, "ip", "x"))


if __name__ == "__main__":
    unittest.main()
