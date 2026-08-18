"""Tests for store.py — the SQLite case store (isolated via SPYGLASS_HOME)."""

import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

store = imp("store")


def _website_result(ips, subs):
    return {
        "dns_records": {"A": ", ".join(ips)},
        "subdomains": subs,
        "whois": {"Organization": "Acme Inc", "Registrant Email": "a@acme.com"},
    }


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"SPYGLASS_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_store_and_list(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        cases = store.list_cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["target"], "x.com")
        self.assertEqual(cases[0]["qtype"], "website")
        self.assertEqual(cases[0]["count"], 1)

    def test_diff_added_and_removed(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com", "a.x.com"]), "website", "x.com")
        store.store_result(_website_result(["1.2.3.4", "5.6.7.8"], ["www.x.com", "b.x.com"]), "website", "x.com")
        d = store.diff("x.com", "website")
        self.assertNotIn("error", d)
        self.assertIn("domain:b.x.com", d["added"])
        self.assertIn("ip:5.6.7.8", d["added"])
        self.assertIn("domain:a.x.com", d["removed"])
        self.assertNotIn("domain:www.x.com", d["added"] + d["removed"])

    def test_diff_needs_two_runs(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        self.assertIn("error", store.diff("x.com", "website"))

    def test_timeline(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        rows = store.timeline("x.com", "website")
        self.assertEqual(len(rows), 1)
        self.assertIn("ip:1.2.3.4", rows[0]["entities"])

    def test_export_profile_merges_qtypes(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        store.store_result({"query": "x.com", "type": "domain", "ahmia": []}, "darkweb", "x.com")
        profile = store.export_profile("x.com")
        self.assertEqual(profile["target"], "x.com")
        self.assertEqual(profile["schema_version"], 1)
        self.assertIn("website", profile["results"])
        self.assertIn("darkweb", profile["results"])
        self.assertIn("www.x.com", profile["entities"]["domain"])

    def test_entities_website(self):
        ents = store._entities(_website_result(["1.2.3.4"], ["www.x.com"]), "website")
        kv = {f"{k}:{v}" for k, v in ents}
        self.assertIn("ip:1.2.3.4", kv)
        self.assertIn("domain:www.x.com", kv)
        self.assertIn("org:acme inc", kv)
        self.assertIn("email:a@acme.com", kv)


if __name__ == "__main__":
    unittest.main()
