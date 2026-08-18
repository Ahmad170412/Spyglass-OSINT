"""Tests for darkweb.py's pure parsers and keyless/keyed logic (no network)."""

import json
import os
import unittest
from unittest import mock

from helpers import imp

dw = imp("darkweb")


def _curl_mock(stdout="", returncode=0):
    return mock.Mock(stdout=stdout, returncode=returncode)


class DetectTypeTest(unittest.TestCase):
    def test_email(self):
        self.assertEqual(dw._detect_type("user@example.com"), "email")

    def test_ip(self):
        self.assertEqual(dw._detect_type("8.8.8.8"), "ip")
        self.assertEqual(dw._detect_type("2001:db8::1"), "ip")

    def test_phone(self):
        self.assertEqual(dw._detect_type("+1 555 123 4567"), "phone")

    def test_domain(self):
        self.assertEqual(dw._detect_type("example.com"), "domain")

    def test_username(self):
        self.assertEqual(dw._detect_type("janedoe"), "username")


class HiddenInputsTest(unittest.TestCase):
    def test_extracts_hidden_fields(self):
        html = (
            '<input id="id_q" type="search" name="q">'
            '<input type="hidden" name="d96cab" value="7d82d3">'
            '<input type="hidden" name="token" value="a&amp;b">'
        )
        params = dw._parse_hidden_inputs(html)
        self.assertEqual(params["d96cab"], "7d82d3")
        self.assertEqual(params["token"], "a&b")
        self.assertNotIn("q", params)

    def test_ignores_non_hidden(self):
        self.assertEqual(dw._parse_hidden_inputs('<input type="text" name="x" value="y">'), {})


class AhmiaParseTest(unittest.TestCase):
    def test_full_result_block(self):
        html = """
        <html><body>
        <ol class="searchResults">
          <li class="result">
            <h4>
              <a href="/redirect/?search_term=test&redirect_url=http%3A%2F%2Fabc123.onion">
                Example Market
              </a>
            </h4>
            <p>A hidden-service description</p>
            <cite>abc123.onion</cite>
            &mdash; <span class="lastSeen" data-timestamp="1700000000">x</span> &mdash;
          </li>
          <li class="result">
            <h4><a href="/redirect/?search_term=test&redirect_url=http://def456.onion/">Plain title</a></h4>
            <p>No description provided</p>
            <cite>def456.onion</cite>
          </li>
        </ol>
        </body></html>
        """
        results = dw._parse_ahmia_html(html)
        self.assertEqual(len(results), 2)

        r0 = results[0]
        self.assertEqual(r0["url"], "http://abc123.onion")
        self.assertEqual(r0["title"], "Example Market")
        self.assertEqual(r0["description"], "A hidden-service description")
        self.assertEqual(r0["domain"], "abc123.onion")
        self.assertRegex(r0["last_seen"], r"\d{4}-\d{2}-\d{2}")

        r1 = results[1]
        self.assertEqual(r1["url"], "http://def456.onion/")
        self.assertEqual(r1["title"], "Plain title")
        self.assertEqual(r1["last_seen"], "")

    def test_skips_non_http_urls(self):
        html = (
            '<ol class="searchResults"><li class="result">'
            '<h4><a href="/redirect/?redirect_url=ftp://bad.onion">x</a></h4>'
            '</li></ol>'
        )
        self.assertEqual(dw._parse_ahmia_html(html), [])

    def test_no_results_markup(self):
        self.assertEqual(dw._parse_ahmia_html("<html><body>no matches</body></html>"), [])

    def test_deduplicates_by_url(self):
        block = (
            '<li class="result">'
            '<h4><a href="/redirect/?redirect_url=http://dup.onion">A</a></h4>'
            '</li>'
        )
        html = f'<ol class="searchResults">{block}{block}</ol>'
        results = dw._parse_ahmia_html(html)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "http://dup.onion")

    def test_caps_results(self):
        blocks = "".join(
            f'<li class="result"><h4><a href="/redirect/?redirect_url=http://r{i}.onion">T</a></h4></li>'
            for i in range(dw._AHMIA_LIMIT + 25)
        )
        html = f'<ol class="searchResults">{blocks}</ol>'
        self.assertEqual(len(dw._parse_ahmia_html(html)), dw._AHMIA_LIMIT)


class AhmiaFetchTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(dw.utils, "_CURL", "/usr/bin/curl")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_two_step_and_parse(self):
        form = '<input type="hidden" name="d96cab" value="7d82d3">'
        results = (
            '<ol class="searchResults"><li class="result">'
            '<h4><a href="/redirect/?redirect_url=http://abc.onion">T</a></h4>'
            '</li></ol>'
        )
        with mock.patch.object(dw, "_curl_text", side_effect=[form, results]) as curl:
            out = dw._ahmia("test")
        self.assertEqual(curl.call_count, 2)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["url"], "http://abc.onion")

    def test_degradates_to_empty_on_failure(self):
        with mock.patch.object(dw, "_curl_text", side_effect=Exception("boom")):
            self.assertEqual(dw._ahmia("test"), [])


class PwnedPasswordTest(unittest.TestCase):
    PREFIX = "5BAA6"  # SHA-1("password") prefix
    SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def setUp(self):
        patcher = mock.patch.object(dw.utils, "_CURL", "/usr/bin/curl")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_pwned_match(self):
        body = f"{self.SUFFIX}:3789800\r\nOTHER:1\r\n"
        with mock.patch.object(dw.subprocess, "run", return_value=_curl_mock(body)):
            out = dw.pwned_password("password")
        self.assertTrue(out["pwned"])
        self.assertEqual(out["count"], 3789800)
        # The password/hash must never appear in the result.
        self.assertNotIn("password", str(out))

    def test_clean(self):
        with mock.patch.object(dw.subprocess, "run", return_value=_curl_mock("DEADBEEF:5\r\n")):
            out = dw.pwned_password("password")
        self.assertFalse(out["pwned"])
        self.assertEqual(out["count"], 0)

    def test_empty_password(self):
        out = dw.pwned_password("")
        self.assertIn("error", out)

    def test_transport_failure(self):
        with mock.patch.object(dw.subprocess, "run", side_effect=OSError("net")):
            out = dw.pwned_password("password")
        self.assertIn("error", out)


class IntelXTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(dw.utils, "_CURL", "/usr/bin/curl")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_key_skips(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(dw._intelx("user@example.com", "email"))

    def test_parses_selectors(self):
        data = {"status": "0", "total": 2,
                "selectors": [
                    {"selectvalue": "u1", "value": "user@example.com"},
                    {"selectvalue": "u2", "value": "user@corp.com"},
                ]}
        with mock.patch.dict(os.environ, {"INTELX_API_KEY": "k"}, clear=False):
            with mock.patch.object(dw.subprocess, "run",
                                   return_value=_curl_mock(json.dumps(data))):
                out = dw._intelx("user@example.com", "email")
        self.assertEqual(out["total"], 2)
        self.assertIn("user@corp.com", out["results"])

    def test_non_dict_response(self):
        with mock.patch.dict(os.environ, {"INTELX_API_KEY": "k"}, clear=False):
            with mock.patch.object(dw.subprocess, "run", return_value=_curl_mock("[]")):
                self.assertIsNone(dw._intelx("x.com", "domain"))


class HibpTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(dw.utils, "_CURL", "/usr/bin/curl")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_key_skips(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(dw._hibp_account("user@example.com"))

    def test_parses_breaches(self):
        data = [{"Name": "Adobe", "BreachDate": "2013-10-04",
                 "Domain": "adobe.com", "DataClasses": ["Email addresses"]}]
        with mock.patch.dict(os.environ, {"HIBP_API_KEY": "k"}, clear=False):
            with mock.patch.object(dw.subprocess, "run",
                                   return_value=_curl_mock(json.dumps(data))):
                out = dw._hibp_account("user@example.com")
        self.assertEqual(out["breaches"][0]["name"], "Adobe")
        self.assertEqual(out["breaches"][0]["date"], "2013-10-04")

    def test_404_means_clean(self):
        with mock.patch.dict(os.environ, {"HIBP_API_KEY": "k"}, clear=False):
            with mock.patch.object(dw.subprocess, "run",
                                   return_value=_curl_mock("", returncode=404)):
                out = dw._hibp_account("clean@example.com")
        self.assertEqual(out["breaches"], [])


class DarkwebOrchestrationTest(unittest.TestCase):
    def test_breach_only_for_identity_types(self):
        with mock.patch.object(dw, "_ahmia", return_value=[]), \
             mock.patch.object(dw, "_intelx", return_value=None), \
             mock.patch.object(dw, "_hibp_account", return_value=None), \
             mock.patch.object(dw.breach, "check",
                               return_value={"found": 0, "sources": [], "fields": []}) as br:
            dw.darkweb("user@example.com", "email")
            self.assertEqual(br.call_count, 1)
            dw.darkweb("example.com", "domain")
            self.assertEqual(br.call_count, 1)  # domain must not call breach.check

    def test_hibp_only_for_email(self):
        with mock.patch.object(dw, "_ahmia", return_value=[]), \
             mock.patch.object(dw, "_intelx", return_value=None), \
             mock.patch.object(dw.breach, "check", return_value={}), \
             mock.patch.object(dw, "_hibp_account", return_value=None) as hibp:
            dw.darkweb("user@example.com", "email")
            dw.darkweb("example.com", "domain")
        self.assertEqual(hibp.call_count, 1)


class DarkwebReportExportTest(unittest.TestCase):
    RESULT = {
        "query": "user@example.com",
        "type": "email",
        "ahmia": [{"title": "T", "url": "http://abc.onion", "description": "d",
                   "domain": "abc.onion", "last_seen": "2023-11-14"}],
        "breach": {"found": 1, "sources": [{"name": "Adobe", "date": "2013"}],
                   "fields": ["Email addresses"]},
        "intelx": None,
        "hibp": {"breaches": [{"name": "Adobe", "date": "2013-10-04",
                               "domain": "adobe.com", "data_classes": []}]},
    }

    def test_report_renders(self):
        rep = imp("report")
        md = rep.render(self.RESULT, "darkweb", "user@example.com")
        self.assertIn("Ahmia .onion index", md)
        self.assertIn("http://abc.onion", md)
        self.assertIn("HaveIBeenPwned", md)
        self.assertIn("Adobe", md)

    def test_export_json_roundtrip(self):
        import json
        exp = imp("export")
        path = exp.json_output(self.RESULT, "user@example.com", "darkweb")
        try:
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["ahmia"][0]["url"], "http://abc.onion")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
