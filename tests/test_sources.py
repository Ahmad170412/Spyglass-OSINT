"""Tests for the three sources added to close the coverage gaps.

Each fixture is a real captured response, trimmed to the fields the parser
reads. A hand-written fixture pins a contract nobody has: the whole point of
these tests is that they fail the moment a real source changes shape, which is
the failure they exist to catch. What is *not* tested is the network — no test
here makes a request.
"""

import json
import unittest
from unittest import mock

from helpers import imp

web = imp("website")
ipmod = imp("ip")


# ── RapidDNS ────────────────────────────────────────────────────────────
# Trimmed from a live https://rapiddns.io/subdomain/example.com?full=1 table.
# Cell order is name, IP, record type, last-seen date.
_RAPIDDNS_HTML = """
<table><tbody>
<tr><th>Domain</th><th>IP</th><th>Type</th><th>Date</th></tr>
<tr><td>example.com</td><td>104.20.23.154</td><td>A</td><td>2026-09-14</td></tr>
<tr><td>www.example.com</td><td>104.20.23.154</td><td>A</td><td>2026-09-14</td></tr>
<tr><td>mail.example.com</td><td>172.66.147.243</td><td>A</td><td>2026-09-10</td></tr>
<tr><td>old.example.com</td><td>198.51.100.7</td><td>A</td><td>2021-04-02</td></tr>
</tbody></table>
"""


class RapidDNSTest(unittest.TestCase):
    def _run(self, body):
        with mock.patch.object(web, "_http_body", return_value=body):
            return web._rapiddns("example.com")

    def test_returns_names_and_resolution_rows(self):
        subs, rows = self._run(_RAPIDDNS_HTML)
        self.assertEqual(subs, {"example.com", "www.example.com",
                                "mail.example.com", "old.example.com"})
        self.assertEqual(len(rows), 4)

    def test_rows_carry_ip_type_and_last_seen(self):
        _subs, rows = self._run(_RAPIDDNS_HTML)
        self.assertIn(("old.example.com", "198.51.100.7", "A", "2021-04-02"), rows)

    def test_a_stale_record_is_preserved_not_filtered(self):
        # The point of passive DNS: a name last resolved in 2021 is a finding,
        # not noise. Anything that dropped old records would delete the signal.
        _subs, rows = self._run(_RAPIDDNS_HTML)
        self.assertTrue(any(r[3].startswith("2021") for r in rows))

    def test_names_outside_the_target_are_rejected(self):
        # A RapidDNS table lists the registrable domain and siblings. Accepting
        # a sibling would attribute someone else's host to the target, which is
        # the same misattribution the suffix-matching subdomain bug caused.
        body = _RAPIDDNS_HTML.replace(
            "<td>mail.example.com</td>", "<td>mail.notexample.com</td>")
        subs, rows = self._run(body)
        self.assertNotIn("mail.notexample.com", subs)
        self.assertEqual([r for r in rows if r[0] == "mail.notexample.com"], [])

    def test_a_suffix_lookalike_is_rejected(self):
        # "notexample.com" ends with the string "example.com" but is not a
        # subdomain of it. Matching must require a label boundary.
        body = _RAPIDDNS_HTML.replace(
            "<td>mail.example.com</td>", "<td>x.notexample.com</td>")
        subs, _rows = self._run(body)
        self.assertNotIn("x.notexample.com", subs)

    def test_a_layout_change_does_not_file_an_ip_as_a_name(self):
        # Two cells instead of four: the parser must drop the row, not guess
        # that the IP column is a hostname.
        body = "<table><tr><td>example.com</td><td>104.20.23.154</td></tr></table>"
        subs, rows = self._run(body)
        self.assertEqual(rows, [])
        self.assertEqual(subs, set())

    def test_an_empty_table_is_not_an_error(self):
        for body in ("", "No results", "<html>" + "x" * 10 + "</html>"):
            subs, rows = self._run(body)
            self.assertEqual((subs, rows), (set(), []))


# ── urlscan.io ──────────────────────────────────────────────────────────
# Trimmed from a live https://urlscan.io/api/v1/search/?q=domain:example.com
_URLSCAN = {
    "total": 3,
    "results": [
        {"_id": "a", "task": {"time": "2026-09-29T01:24:14.316Z"},
         "page": {"domain": "example.com", "ip": "104.20.23.154",
                  "asn": "AS13335", "server": "cloudflare",
                  "title": "Example Domain", "url": "https://example.com/"}},
        {"_id": "b", "task": {"time": "2026-08-02T10:00:00.000Z"},
         "page": {"domain": "www.example.com", "ip": "172.66.147.243",
                  "asn": "AS13335", "server": "nginx",
                  "title": "Example", "url": "https://www.example.com/"}},
        {"_id": "c", "task": {"time": "2026-09-28T00:00:00.000Z"},
         "page": {"domain": "downdetector.com", "ip": "2606:4700::6812:17b3",
                  "url": "https://downdetector.com/status/mx-merchant/map/"}},
    ],
}


class UrlscanTest(unittest.TestCase):
    def _run(self, payload):
        with mock.patch.object(web, "_http_json", return_value=payload):
            return web._urlscan("example.com")

    def test_observed_pages_are_collected_with_provenance(self):
        out = self._run(_URLSCAN)
        urls = {o["url"] for o in out["observed"]}
        self.assertIn("https://example.com/", urls)
        self.assertIn("https://www.example.com/", urls)
        first = next(o for o in out["observed"] if o["url"] == "https://example.com/")
        self.assertEqual(first["asn"], "AS13335")
        self.assertEqual(first["scanned"], "2026-09-29")

    def test_a_third_party_mention_is_not_an_asset(self):
        # urlscan's domain: operator also matches pages that link to the target.
        # downdetector.com mentions example.com; it is not its infrastructure,
        # and counting it as one would put a stranger's host in the target's
        # asset list.
        out = self._run(_URLSCAN)
        urls = " ".join(o["url"] for o in out["observed"])
        self.assertNotIn("downdetector", urls)
        self.assertNotIn("2606:4700::6812:17b3", out.get("observed_ips", []))
        self.assertTrue(any("downdetector.com" in r
                            for r in out.get("referenced_by", [])))

    def test_historical_servers_are_reported_and_deduped(self):
        out = self._run(_URLSCAN)
        # cloudflare and nginx were both seen, at different times — a passive
        # view of infrastructure change that a single live fetch cannot give.
        self.assertEqual(out["historical_servers"], ["cloudflare", "nginx"])

    def test_observed_ips_include_ipv6(self):
        payload = {"results": [{"task": {"time": "2026-01-01T00:00:00Z"},
                                "page": {"domain": "example.com",
                                         "ip": "2606:4700::6812:17b3"}}]}
        out = self._run(payload)
        self.assertIn("2606:4700::6812:17b3", out["observed_ips"])

    def test_repeated_scans_of_one_url_collapse_to_a_single_row(self):
        # urlscan returns one row per scan, so a popular page arrives many times
        # against different anycast addresses. Reported raw, the table opens on
        # the same link four times.
        payload = {"results": [
            {"task": {"time": "2026-09-28T00:00:00Z"},
             "page": {"domain": "example.com", "url": "https://example.com/",
                      "ip": "1.1.1.1", "asn": "AS13335", "server": "cloudflare"}},
            {"task": {"time": "2026-09-29T00:00:00Z"},
             "page": {"domain": "example.com", "url": "https://example.com/",
                      "ip": "2.2.2.2", "asn": "AS13335", "server": "cloudflare"}},
            {"task": {"time": "2026-09-29T01:00:00Z"},
             "page": {"domain": "example.com", "url": "https://example.com/",
                      "ip": "3.3.3.3", "asn": "AS13335", "server": "nginx"}},
        ]}
        out = self._run(payload)
        self.assertEqual(len(out["observed"]), 1)
        row = out["observed"][0]
        self.assertEqual(row["scans"], 3)
        # Newest scan wins, and the addresses seen are summarised not listed.
        self.assertEqual(row["scanned"], "2026-09-29")
        self.assertEqual(row["server"], "nginx")
        self.assertIn("+2 more", row["ip"])

    def test_a_malformed_response_is_not_an_error(self):
        for payload in ({}, {"results": "nonsense"}, [], None):
            self.assertEqual(self._run(payload), {})

    def test_an_observation_with_no_url_is_dropped_not_rendered(self):
        # A row of empty strings in the report's main table reads as "a scan
        # happened and told us nothing", which is worse than an absent section.
        payload = {"results": [{"_id": "z", "page": {}}]}
        out = self._run(payload)
        self.assertNotIn("observed", out)

    def test_a_non_dict_page_or_result_is_skipped(self):
        payload = {"results": ["a string", 7, None,
                               {"page": "not a dict"}, {"page": {"domain": "example.com",
                                                                 "url": "https://example.com/"}}]}
        out = self._run(payload)
        self.assertEqual([o["url"] for o in out["observed"]], ["https://example.com/"])


# ── ipwho.is ────────────────────────────────────────────────────────────
# Trimmed from a live https://ipwho.is/8.8.8.8
_IPWHOIS = {
    "success": True, "country": "United States", "region": "California",
    "city": "San Jose", "latitude": 37.3393939, "longitude": -121.8949553,
    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC",
                   "domain": "google.com"},
    "timezone": {"id": "America/Los_Angeles"},
}


class IpwhoisTest(unittest.TestCase):
    def test_normalises_to_the_same_shape_as_the_primary_source(self):
        with mock.patch.object(ipmod, "_curl_json", return_value=_IPWHOIS):
            out = ipmod._ipwhois("8.8.8.8")
        self.assertEqual(out["country"], "United States")
        self.assertEqual(out["as"], "AS15169")
        self.assertEqual(out["org"], "Google LLC")
        self.assertEqual(out["location"], "37.3393939,-121.8949553")
        self.assertEqual(out["timezone"], "America/Los_Angeles")

    def test_failure_is_reported_as_nothing_not_as_a_blank_location(self):
        for payload in ({}, {"success": False}, None, "nonsense", []):
            with mock.patch.object(ipmod, "_curl_json", return_value=payload):
                self.assertIsNone(ipmod._ipwhois("8.8.8.8"))

    def test_the_fallback_is_used_only_when_the_primary_fails(self):
        calls = []

        def fake(url):
            calls.append(url)
            return _IPWHOIS if "ipwho" in url else None

        with mock.patch.object(ipmod, "_curl_json", side_effect=fake):
            out = ipmod._geolocate("8.8.8.8")
        self.assertTrue(any("ip-api" in c for c in calls))
        self.assertTrue(any("ipwho" in c for c in calls))
        self.assertIn("fallback", out["_source"])

    def test_the_primary_is_preferred_and_says_so(self):
        primary = {"country": "X", "region": "Y", "city": "Z"}
        with mock.patch.object(ipmod, "_ip_api", return_value=primary), \
             mock.patch.object(ipmod, "_ipwhois") as fb:
            out = ipmod._geolocate("8.8.8.8")
        fb.assert_not_called()
        self.assertEqual(out["_source"], "ip-api.com")

    def test_provenance_is_kept_because_the_two_sources_disagree(self):
        # Measured: ip-api.com places 8.8.8.8 in Ashburn/Virginia and ipwho.is
        # in San Jose/California, on opposite timezones. Both agree on AS15169.
        # A reader cannot tell them apart if both render as a bare city, so the
        # source travels with the answer.
        primary = {"country": "United States", "city": "Ashburn",
                   "as": "AS15169 Google LLC"}
        with mock.patch.object(ipmod, "_ip_api", return_value=primary), \
             mock.patch.object(ipmod, "_ipwhois", return_value=_IPWHOIS):
            out = ipmod._geolocate("8.8.8.8")
        self.assertEqual(out["city"], "Ashburn")
        self.assertEqual(out["_source"], "ip-api.com")
        self.assertNotEqual(out["city"], "San Jose")
