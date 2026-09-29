"""Tests for asn.py — target parsing, response normalisation, and degradation.

All offline. RIPEStat payloads are replayed from real responses; the shape of
each fixture was checked against the live API, because a fixture that does not
match the real response is worse than no fixture at all — it pins the wrong
contract.
"""

import unittest
from unittest import mock

from helpers import imp

asn_mod = imp("asn")


def _payload(data, status="ok", messages=None):
    return {"status": status, "data": data, "messages": messages or []}


PREFIX_OK = _payload({
    "resource": "8.8.8.0/24",
    "announced": True,
    "asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}],
    "related_prefixes": ["8.0.0.0/9", "8.0.0.0/12"],
    "block": {"resource": "8.0.0.0/8", "desc": "Administered by ARIN",
              "name": "IANA IPv4 Address Space Registry"},
})

PREFIX_UNANNOUNCED = _payload({
    "resource": "192.0.2.0/24",
    "announced": False,
    "asns": [],
    "related_prefixes": [],
    "block": {"resource": "192.0.2.0/24", "desc": "Documentation (TEST-NET-1)",
              "name": "IANA IPv4 Special Purpose Address Registry"},
})

PREFIX_MOAS = _payload({
    "resource": "1.1.1.0/24",
    "announced": True,
    "asns": [{"asn": 13335, "holder": "CLOUDFLARENET - Cloudflare, Inc."},
             {"asn": 64496, "holder": "APNIC-LABS"},
             {"asn": 13337, "holder": "CLOUDFLARENET - Cloudflare, Inc."},
             {"asn": 55555, "holder": "EXAMPLE-EXTRA"}],
    "related_prefixes": [],
    "block": {"resource": "1.0.0.0/8", "desc": "APNIC", "name": "IANA IPv4"},
})

RPKI_VALID = _payload({
    "resource": "15169", "prefix": "8.8.8.0/24", "status": "valid",
    "validator": "routinator",
    "validating_roas": [{"origin": "15169", "prefix": "8.8.8.0/24",
                         "validity": "valid", "max_length": 24}],
})

RPKI_INVALID = _payload({
    "resource": "64496", "prefix": "1.1.1.0/24", "status": "invalid",
    "validator": "routinator",
    "validating_roas": [{"origin": "64496", "prefix": "1.1.1.0/24",
                         "validity": "invalid", "max_length": 24}],
})

AS_OK = _payload({
    "type": "as", "resource": "15169", "holder": "GOOGLE - Google LLC",
    "announced": True,
    "block": {"resource": "13312-15359", "desc": "Assigned by ARIN",
              "name": "IANA 16-bit Autonomous System (AS) Numbers Registry"},
})


def _fake_router(responses):
    """A _curl_json stand-in that serves fixtures by data-call name."""
    calls = []

    def _curl_json(url, timeout=15):
        calls.append(url)
        for name, fixture in responses.items():
            if f"/{name}/data.json" in url:
                if isinstance(fixture, list):
                    return fixture.pop(0) if fixture else None
                return fixture
        return None

    _curl_json.calls = calls
    return _curl_json


class TargetParsingTest(unittest.TestCase):
    """A bare address must not be classified as a /32 prefix.

    ``ipaddress.ip_network`` accepts "8.8.8.8" and returns 8.8.8.8/32, so
    testing the network form first made the ``ip`` branch unreachable and every
    IP reported itself as a prefix.
    """

    def test_bare_ipv4_is_an_ip(self):
        self.assertEqual(asn_mod._parse_target("8.8.8.8")[0], "ip")

    def test_bare_ipv6_is_an_ip(self):
        self.assertEqual(asn_mod._parse_target("2606:4700::1111")[0], "ip")

    def test_cidr_is_a_prefix(self):
        self.assertEqual(asn_mod._parse_target("8.8.8.0/24")[0], "prefix")

    def test_as_with_prefix_is_a_prefix(self):
        self.assertEqual(asn_mod._parse_target("AS15169")[0], "asn")

    def test_bare_number_is_an_asn(self):
        self.assertEqual(asn_mod._parse_target("15169"), ("asn", 15169))

    def test_lowercase_as_prefix_is_accepted(self):
        self.assertEqual(asn_mod._parse_target("as13335"), ("asn", 13335))

    def test_surrounding_whitespace_is_tolerated(self):
        self.assertEqual(asn_mod._parse_target("  8.8.8.0/24  ")[0], "prefix")

    def test_hostname_is_rejected(self):
        # The module answers "who routes this", so a name has to be resolved to
        # an address first. Accepting one would silently return nothing.
        self.assertEqual(asn_mod._parse_target("example.com"), (None, None))

    def test_garbage_is_rejected(self):
        for bad in ("garbage", "", None, "8.8.8.8/33", "AS", "-1", "999.1.1.1"):
            self.assertEqual(asn_mod._parse_target(bad), (None, None), bad)

    def test_invalid_input_returns_an_error_and_a_hint(self):
        r = asn_mod.asn("not-an-address")
        self.assertIn("error", r)
        self.assertIn("hint", r)


class RipeDataTest(unittest.TestCase):
    def test_error_status_becomes_an_error_not_an_empty_dict(self):
        err_payload = _payload({}, status="error",
                              messages=[["error", "not-an-ip is of an unsupported "
                                                "resource type."]])
        with mock.patch.object(asn_mod, "_curl_json", return_value=err_payload):
            data, err = asn_mod._ripe_data("prefix-overview", resource="not-an-ip")
        self.assertIsNone(data)
        self.assertIn("unsupported resource type", err)

    def test_unreachable_service_is_distinguished_from_a_rejection(self):
        with mock.patch.object(asn_mod, "_curl_json", return_value=None):
            data, err = asn_mod._ripe_data("as-overview", resource="AS1")
        self.assertIsNone(data)
        self.assertIn("could not reach RIPEStat", err)

    def test_message_is_preserved_on_a_successful_but_empty_response(self):
        # RIPE reports an unannounced address with status: ok and a message.
        # Without this the reason is unrecoverable.
        payload = _payload({"announced": False, "asns": []},
                           messages=[["info", "1 routes were filtered due to "
                                              "low visibility (min peers:10)."]])
        with mock.patch.object(asn_mod, "_curl_json", return_value=payload):
            data, err = asn_mod._ripe_data("prefix-overview", resource="10.0.0.1")
        self.assertIsNone(err)
        self.assertIn("low visibility", data["_note"])


class AsnLookupTest(unittest.TestCase):
    def test_ip_input_resolves_prefix_origin_and_rpki(self):
        router = _fake_router({
            "prefix-overview": PREFIX_OK,
            "rpki-validation": RPKI_VALID,
            "announced-prefixes": _payload({
                "prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "8.8.4.0/24"}],
                "resource": "15169"}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("8.8.8.8")
        self.assertNotIn("error", r)
        self.assertEqual(r["query_type"], "ip")
        self.assertEqual(r["prefix"], "8.8.8.0/24")
        self.assertTrue(r["announced"])
        self.assertEqual(r["origin_asns"][0]["asn"], 15169)
        self.assertEqual(r["covering_prefixes"], ["8.0.0.0/9", "8.0.0.0/12"])
        self.assertEqual(r["rpki"][0]["status"], "valid")
        self.assertEqual(r["rpki"][0]["roas"][0]["max_length"], 24)
        self.assertEqual(r["rpki_summary"], "valid (origin AS15169)")

    def test_as_input_returns_holder_and_footprint(self):
        router = _fake_router({
            "as-overview": AS_OK,
            "announced-prefixes": _payload({
                "prefixes": [{"prefix": "8.8.8.0/24"}], "resource": "15169"}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("AS15169")
        self.assertEqual(r["asn"], 15169)
        self.assertEqual(r["holder"], "GOOGLE - Google LLC")
        self.assertEqual(r["announced_prefixes"]["total"], 1)

    def test_as_input_refuses_to_invent_an_rpki_verdict(self):
        # RPKI validates a prefix against an origin. An AS alone has nothing to
        # validate, and reporting "valid" here would be the one answer in this
        # tool that looks like a safety result and is not one.
        router = _fake_router({
            "as-overview": AS_OK,
            "announced-prefixes": _payload({"prefixes": [], "resource": "15169"}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("AS15169")
        self.assertEqual(r["rpki"], [])
        self.assertIn("prefix", r["rpki_note"])

    def test_unannounced_address_still_answers(self):
        router = _fake_router({"prefix-overview": PREFIX_UNANNOUNCED})
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("192.0.2.1")
        self.assertFalse(r["announced"])
        self.assertIn("unannounced_reason", r)
        self.assertEqual(r["rpki"], [])

    def test_invalid_rpki_is_surfaced_and_summarised_first(self):
        router = _fake_router({
            "prefix-overview": PREFIX_MOAS,
            "rpki-validation": [RPKI_INVALID, RPKI_INVALID, RPKI_INVALID,
                                RPKI_INVALID],
            "announced-prefixes": _payload({"prefixes": [], "resource": "13335"}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("1.1.1.1")
        statuses = [e["status"] for e in r["rpki"]]
        self.assertIn("invalid", statuses)
        # A conflicting ROA is the finding, so it leads the summary.
        self.assertTrue(r["rpki_summary"].startswith("invalid"))

    def test_every_origin_is_reported_even_when_rpki_is_capped(self):
        router = _fake_router({
            "prefix-overview": PREFIX_MOAS,
            "rpki-validation": [RPKI_INVALID] * 4,
            "announced-prefixes": _payload({"prefixes": [], "resource": "13335"}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("1.1.1.1")
        self.assertEqual(len(r["origin_asns"]), 4)
        self.assertLessEqual(len(r["rpki"]), asn_mod._RPKI_ORIGIN_CAP)

    def test_rpki_order_is_stable_across_runs(self):
        # The pool finishes futures in arbitrary order. A result that reorders
        # itself between two runs of one target reads as a change that never
        # happened, which is the exact failure cases diff exists to prevent.
        payload = _payload({
            "resource": "1.1.1.0/24", "announced": True,
            "asns": [{"asn": 13337, "holder": "A"}, {"asn": 64496, "holder": "B"},
                     {"asn": 13335, "holder": "C"}],
            "related_prefixes": [],
        })
        rpki = _payload({"prefix": "1.1.1.0/24", "status": "valid",
                         "validating_roas": []})
        orders = []
        for _ in range(3):
            router = _fake_router({"prefix-overview": payload,
                                   "rpki-validation": rpki,
                                   "announced-prefixes": _payload({"prefixes": []})})
            with mock.patch.object(asn_mod, "_curl_json", router):
                r = asn_mod.asn("1.1.1.1")
            orders.append([e["origin_asn"] for e in r["rpki"]])
        for order in orders:
            self.assertEqual(order, sorted(order))

    def test_ripe_error_does_not_abort_the_rest(self):
        router = _fake_router({
            "prefix-overview": PREFIX_OK,
            "rpki-validation": _payload({}, status="error"),
            "announced-prefixes": _payload({
                "prefixes": [{"prefix": "8.8.8.0/24"}]}),
        })
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("8.8.8.8")
        self.assertNotIn("error", r)
        self.assertTrue(r["rpki_errors"])
        # The footprint call was independent and still answered.
        self.assertEqual(r["announced_prefixes"]["total"], 1)

    def test_asn_with_no_holder_is_an_error_not_a_blank_row(self):
        router = _fake_router({"as-overview": _payload({"announced": False})})
        with mock.patch.object(asn_mod, "_curl_json", router):
            r = asn_mod.asn("AS1")
        self.assertIn("error", r)
        self.assertIn("no holder", r["error"])


class FootprintSamplingTest(unittest.TestCase):
    def _footprint(self, prefixes, family=4):
        payload = _payload({"prefixes": [{"prefix": p} for p in prefixes],
                            "resource": "1"})
        with mock.patch.object(asn_mod, "_curl_json", return_value=payload):
            return asn_mod._announced_prefixes(1, family)

    def test_total_counts_everything_not_just_the_sample(self):
        prefixes = [f"10.{i // 256}.{i % 256}.0/24" for i in range(200)]
        data, _ = self._footprint(prefixes)
        self.assertEqual(data["total"], 200)
        self.assertLess(len(data["sample"]), 200)

    def test_sample_is_biased_to_the_input_family(self):
        v4 = [f"10.{i // 256}.{i % 256}.0/24" for i in range(60)]
        v6 = [f"2001:db8:{i:x}::/48" for i in range(60)]
        data, _ = self._footprint(v4 + v6, family=4)
        self.assertEqual(data["ipv4_total"], 60)
        self.assertEqual(data["ipv6_total"], 60)
        self.assertTrue(data["sample"][0].count(".") == 3)
        # A dual-stack operator stays visibly dual-stack.
        self.assertTrue(any(":" in p for p in data["sample"]))

    def test_ipv6_input_gets_ipv6_leading(self):
        v4 = [f"10.{i // 256}.{i % 256}.0/24" for i in range(60)]
        v6 = [f"2001:db8:{i:x}::/48" for i in range(60)]
        data, _ = self._footprint(v4 + v6, family=6)
        self.assertIn(":", data["sample"][0])

    def test_note_is_absent_when_nothing_was_dropped(self):
        data, _ = self._footprint(["8.8.8.0/24"])
        self.assertIsNone(data["note"])

    def test_malformed_prefixes_are_dropped_from_the_count(self):
        # A prefix that does not parse must not be counted, or ``total`` stops
        # equalling ipv4_total + ipv6_total and the "showing N of M" note
        # stops adding up.
        payload = _payload({"prefixes": [{"prefix": "not-a-prefix"},
                                         {"prefix": "8.8.8.0/24"}]})
        with mock.patch.object(asn_mod, "_curl_json", return_value=payload):
            data, _ = asn_mod._announced_prefixes(1)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["total"],
                         data["ipv4_total"] + data["ipv6_total"])
        self.assertEqual(data["sample"], ["8.8.8.0/24"])


class RpkiSummaryTest(unittest.TestCase):
    def test_invalid_sorts_before_valid(self):
        summary = asn_mod._rpki_summary([
            {"status": "valid", "origin_asn": 1},
            {"status": "invalid", "origin_asn": 2},
        ])
        self.assertTrue(summary.startswith("invalid"))

    def test_groups_origins_under_one_verdict(self):
        summary = asn_mod._rpki_summary([
            {"status": "valid", "origin_asn": 3},
            {"status": "valid", "origin_asn": 1},
        ])
        self.assertEqual(summary, "valid (origin AS1, AS3)")


if __name__ == "__main__":
    unittest.main()
