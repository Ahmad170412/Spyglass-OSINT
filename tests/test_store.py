"""Tests for store.py — the SQLite case store (isolated via SPYGLASS_HOME)."""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from helpers import imp

store = imp("store")
display = imp("display")


def _silence_store_chatter(test):
    """Mute the encryption-status line store_result prints on every write.

    It is a real operator-facing message, so the tests that *assert* on it
    patch these themselves; everything else only needs it to stay off the
    console while the suite runs.
    """
    for name in ("info", "warn"):
        patcher = mock.patch.object(display, name)
        patcher.start()
        test.addCleanup(patcher.stop)


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
        _silence_store_chatter(self)

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


def _phone_result(domains, e164="+6585260980"):
    return {
        "phonenumbers": {"valid": True, "e164": e164, "region": "SG"},
        "ignorant": list(domains),
        "phoneinfoga": {},
        "breach": {"found": 0, "sources": [], "fields": []},
    }


class EntityIndexCoverageTest(unittest.TestCase):
    """Every module must produce an index.

    ``phone``, ``metadata`` and ``opsec`` had no branch in the extractor chain,
    so ``cases diff`` and ``cases timeline`` reported zero entities for them and
    looked indistinguishable from a target that had not changed. A module that
    ships with no extractor at all now falls back to shape inference, so the
    coverage is the default rather than something to remember.
    """

    def _kv(self, result, qtype):
        return {f"{k}:{v}" for k, v in store._entities(result, qtype)}

    def test_phone_indexes_its_registrations_and_number(self):
        kv = self._kv(_phone_result(["instagram.com", "facebook.com"]), "phone")
        self.assertIn("phone:+6585260980", kv)
        self.assertIn("domain:instagram.com", kv)
        self.assertIn("domain:facebook.com", kv)

    def test_phone_indexes_breach_sources(self):
        result = _phone_result([])
        result["breach"] = {"found": 1, "sources": [{"name": "LeakCheck"}]}
        self.assertIn("breach:leakcheck", self._kv(result, "phone"))

    def test_phone_indexes_urls_in_phoneinfoga_output(self):
        # phoneinfoga's schema varies by version; its OSINT sources arrive as
        # URLs, which the walker unwraps to a host.
        result = _phone_result([])
        result["phoneinfoga"] = {"osint": [{"url": "https://t.me/someuser"}]}
        self.assertIn("domain:t.me", self._kv(result, "phone"))

    def test_metadata_indexes_file_digests(self):
        result = {"file_name": "evidence.jpg",
                  "md5": "D41D8CD98F00B204E9800998ECF8427E",
                  "sha256": "ABCDEF"}
        kv = self._kv(result, "metadata")
        self.assertIn("hash:d41d8cd98f00b204e9800998ecf8427e", kv)
        self.assertIn("hash:abcdef", kv)

    def test_metadata_indexes_gps(self):
        result = {"GPS": {"GPSLatitude": 1.3521, "GPSLatitudeRef": "N",
                          "GPSLongitude": 103.8198, "GPSLongitudeRef": "E"}}
        self.assertIn("geo:1.3521,103.8198", self._kv(result, "metadata"))

    def test_southern_and_western_gps_is_signed_by_its_ref(self):
        # exiftool reports magnitude and hemisphere separately, so an unsigned
        # southern position would land on the wrong side of the equator.
        result = {"GPS": {"GPSLatitude": 33.8688, "GPSLatitudeRef": "S",
                          "GPSLongitude": 151.2093, "GPSLongitudeRef": "E"}}
        self.assertIn("geo:-33.8688,151.2093", self._kv(result, "metadata"))

    def test_western_longitude_is_signed_by_its_ref(self):
        result = {"GPS": {"GPSLatitude": 40.7128, "GPSLatitudeRef": "N",
                          "GPSLongitude": 74.006, "GPSLongitudeRef": "W"}}
        self.assertIn("geo:40.7128,-74.006", self._kv(result, "metadata"))

    def test_metadata_does_not_index_the_filename_as_a_domain(self):
        # "evidence.jpg" satisfies every structural rule a domain does.
        kv = self._kv({"file_name": "evidence.jpg", "model": "EOS 5D"}, "metadata")
        self.assertEqual(kv, set())

    def test_opsec_uses_a_separate_kind_from_target_infrastructure(self):
        # opsec reports the machine running Spyglass. Filing that under "ip"
        # would put the operator's address into the target's entity set.
        result = {"direct": {"ip": "203.0.113.9"}, "proxy": {"ip": "198.51.100.7"}}
        kv = self._kv(result, "opsec")
        self.assertIn("operator_ip:203.0.113.9", kv)
        self.assertIn("operator_ip:198.51.100.7", kv)
        self.assertNotIn("ip:203.0.113.9", kv)

    def test_unregistered_module_falls_back_to_shape_inference(self):
        # "newmod" is deliberately not in _EXTRACTORS — that is the point.
        result = {"host": "example.com", "address": "8.8.8.8",
                  "owner": "a@acme.com", "asn": "AS15169",
                  "mirror": "http://mirror.example.org/x",
                  "onion": "abcdefghij234567.onion"}
        kv = self._kv(result, "newmod")
        self.assertIn("domain:example.com", kv)
        self.assertIn("ip:8.8.8.8", kv)
        self.assertIn("email:a@acme.com", kv)
        self.assertIn("asn:as15169", kv)
        self.assertIn("domain:mirror.example.org", kv)
        self.assertIn("onion:abcdefghij234567.onion", kv)

    def test_fallback_ignores_private_handoff_keys(self):
        kv = self._kv({"seen": "a.com", "_staging": {"host": "hidden.com"}}, "newmod")
        self.assertIn("domain:a.com", kv)
        self.assertNotIn("domain:hidden.com", kv)

    def test_fallback_is_bounded(self):
        # An unbounded walk is a latency bug waiting for the module that
        # returns a very large list.
        big = {f"k{i}": f"host{i}.example.com" for i in range(5000)}
        self.assertLessEqual(len(store._entities(big, "newmod")),
                             store._INFER_MAX_VALUES)

    def test_budget_does_not_leak_between_calls(self):
        """The walk budget is per-pass, not per-process.

        It was a module global, so the first result to be walked exhausted it
        and every later walk indexed nothing — which in a long-running web
        console means the second and subsequent ``--store`` runs silently lose
        their entity index. Only a second call can catch this.
        """
        result = {"phoneinfoga": {"osint": [{"url": "https://t.me/someuser"}]}}
        for _ in range(3):
            kv = self._kv(result, "phone")
            self.assertIn("domain:t.me", kv)

    def test_budget_survives_a_large_result(self):
        # A big walk immediately before a small one must not starve the small
        # one, which is what the old shared global did.
        store._entities({f"k{i}": f"h{i}.example.com" for i in range(5000)},
                        "newmod")
        kv = self._kv({"phoneinfoga": {"u": "https://t.me/x"}}, "phone")
        self.assertIn("domain:t.me", kv)

    def test_concurrent_walks_do_not_share_a_budget(self):
        import threading
        seen = []
        errors = []

        def run():
            try:
                seen.append(self._kv({"u": "https://t.me/x"}, "phone"))
            except Exception as exc:  # pragma: no cover - only on a real failure
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        for kv in seen:
            self.assertIn("domain:t.me", kv)

    def test_non_dict_result_yields_no_entities(self):
        self.assertEqual(store._entities(None, "website"), [])
        self.assertEqual(store._entities(["a.com"], "website"), [])

    def test_asn_indexes_origin_and_holder(self):
        result = {"asn": 15169, "holder": "GOOGLE - Google LLC",
                  "prefix": "8.8.8.0/24",
                  "origin_asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}]}
        kv = self._kv(result, "asn")
        self.assertIn("asn:as15169", kv)
        self.assertIn("prefix:8.8.8.0/24", kv)
        self.assertIn("org:google - google llc", kv)

    def test_asn_holder_joins_a_website_run_on_the_same_operator(self):
        # The point of indexing the holder: it is the same organisation string
        # WHOIS produces, so an asn run and a website run land on a shared value.
        kv = self._kv({"asn": 15169, "holder": "GOOGLE - Google LLC"}, "asn")
        self.assertIn("org:google - google llc", kv)

    def test_prefix_inference_in_the_fallback(self):
        kv = self._kv({"routed": "8.8.8.0/24"}, "newmod")
        self.assertIn("prefix:8.8.8.0/24", kv)

    def test_a_slash_address_is_not_mistaken_for_an_ip(self):
        self.assertEqual(store._infer_kind("1.2.3.4/32"), "prefix")
        self.assertEqual(store._infer_kind("1.2.3.4"), "ip")
        self.assertIsNone(store._infer_kind("1.2.3.4/33"))

    def test_every_kind_emitted_is_documented(self):
        # _KINDS is the reference for what a diff line can say; a new kind that
        # is not listed there is a kind nobody can interpret.
        seen = set()
        for result, qtype in (
            (_phone_result(["a.com"]), "phone"),
            ({"md5": "abc"}, "metadata"),
            ({"direct": {"ip": "8.8.8.8"}}, "opsec"),
            (_website_result(["1.2.3.4"], ["a.com"]), "website"),
            ({"ip": "8.8.8.8"}, "ip"),
            ({"ahmia": [{"url": "http://x.onion"}]}, "darkweb"),
            ({"asn": 15169, "holder": "GOOGLE - Google LLC",
              "prefix": "8.8.8.0/24"}, "asn"),
            ({"both": [{"domain": "a.com"}]}, "email"),
            ({"all_4": [{"domain": "a.com"}]}, "username"),
        ):
            seen.update(k for k, _ in store._entities(result, qtype))
        self.assertTrue(seen)
        self.assertEqual(seen - set(store._KINDS), set())


class EntityDiffBehaviourTest(unittest.TestCase):
    """diff is set subtraction over "kind:value", so dedup and casefolding are
    what stop it reporting a change nothing actually made."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"SPYGLASS_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        _silence_store_chatter(self)

    def test_phone_runs_are_now_diffable(self):
        store.store_result(_phone_result(["instagram.com", "facebook.com"]),
                           "phone", "+6585260980")
        store.store_result(_phone_result(["instagram.com", "tiktok.com"]),
                           "phone", "+6585260980")
        d = store.diff("+6585260980", "phone")
        self.assertNotIn("error", d)
        self.assertIn("domain:tiktok.com", d["added"])
        self.assertIn("domain:facebook.com", d["removed"])
        # The number itself is stable, so it is not reported as a change.
        self.assertNotIn("phone:+6585260980", d["added"] + d["removed"])

    def test_opsec_cross_module_diff_keeps_operator_apart(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]),
                           "website", "x.com")
        store.store_result({"direct": {"ip": "203.0.113.9"}}, "opsec", "x.com")
        store.store_result({"direct": {"ip": "203.0.113.10"}}, "opsec", "x.com")
        d = store.diff("x.com", "opsec")
        self.assertIn("operator_ip:203.0.113.10", d["added"])
        self.assertIn("operator_ip:203.0.113.9", d["removed"])
        # And it never shows up mixed in with the target's own infrastructure.
        self.assertNotIn("ip:203.0.113.9", d["added"] + d["removed"])

    def test_case_only_difference_is_not_reported(self):
        store.store_result(_phone_result(["Instagram.com"]), "phone", "+65")
        store.store_result(_phone_result(["instagram.com"]), "phone", "+65")
        d = store.diff("+65", "phone")
        self.assertNotIn("domain:instagram.com", d["added"])
        self.assertNotIn("domain:instagram.com", d["removed"])

    def test_changed_file_digest_is_visible(self):
        store.store_result({"md5": "aaaa"}, "metadata", "evidence.jpg")
        store.store_result({"md5": "bbbb"}, "metadata", "evidence.jpg")
        d = store.diff("evidence.jpg", "metadata")
        self.assertIn("hash:bbbb", d["added"])
        self.assertIn("hash:aaaa", d["removed"])


class StoreEncryptionTest(unittest.TestCase):
    """Encryption at rest.

    The key derivation used a fixed salt, so two operators sharing a password
    derived the same key and the salt was worth nothing. Each row now carries
    its own random salt, and rows written before that change must still open.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"SPYGLASS_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        os.environ.pop("SPYGLASS_STORE_KEY", None)
        os.environ.pop("SPYGLASS_STORE_PASS", None)
        # Each test asserts on the first plaintext warning, so the once-per-
        # process latch has to start clear and be handed back as it was found.
        self._latched = store._plaintext_warned
        store._plaintext_warned = False
        self.addCleanup(setattr, store, "_plaintext_warned", self._latched)
        _silence_store_chatter(self)

    def _raw_results(self):
        """The ``result_json`` column exactly as it sits on disk."""
        con = sqlite3.connect(store._db_path())
        try:
            rows = con.execute("SELECT result_json FROM runs ORDER BY id").fetchall()
        finally:
            con.close()
        return [r[0] for r in rows]

    def test_password_row_is_not_plaintext_on_disk(self):
        os.environ["SPYGLASS_STORE_PASS"] = "correct horse"
        store.store_result({"domain": "secret.example"}, "website", "example.com")
        raw = self._raw_results()[0]
        self.assertNotIn("secret.example", raw)
        self.assertTrue(raw.startswith(f"{store._STORE_PREFIX}:"))

    def test_each_row_derives_its_own_salt(self):
        os.environ["SPYGLASS_STORE_PASS"] = "correct horse"
        for _ in range(2):
            store.store_result({"domain": "example.com"}, "website", "example.com")
        first, second = self._raw_results()
        self.assertNotEqual(first, second)
        salt_a = first.split(":", 2)[1]
        salt_b = second.split(":", 2)[1]
        self.assertNotEqual(salt_a, salt_b)
        # A salt that is really random, not a counter or a hash of the row.
        self.assertEqual(len(store.base64.urlsafe_b64decode(salt_a.encode())),
                         store._SALT_BYTES)

    def test_password_rows_round_trip_through_export(self):
        os.environ["SPYGLASS_STORE_PASS"] = "correct horse"
        store.store_result({"domain": "example.com"}, "website", "example.com")
        profile = store.export_profile("example.com")
        self.assertEqual(profile["results"]["website"], {"domain": "example.com"})

    def test_rows_written_with_the_fixed_salt_still_open(self):
        """Backwards compatibility is the whole reason _LEGACY_SALT survives."""
        from cryptography.fernet import Fernet
        os.environ["SPYGLASS_STORE_PASS"] = "correct horse"
        legacy = Fernet(store._derive("correct horse", store._LEGACY_SALT))
        payload = legacy.encrypt(json.dumps({"domain": "old.example"}).encode()).decode()

        db = store._connect()
        try:
            store._init(db)
            db.execute(
                "INSERT INTO runs (target, qtype, run_at, result_json) "
                "VALUES (?, ?, ?, ?)",
                ("old.example", "website", "2026-01-01T00:00:00", payload),
            )
            db.commit()
        finally:
            db.close()

        profile = store.export_profile("old.example")
        self.assertEqual(profile["results"]["website"], {"domain": "old.example"})

    def test_raw_key_rows_round_trip(self):
        from cryptography.fernet import Fernet
        os.environ["SPYGLASS_STORE_KEY"] = Fernet.generate_key().decode()
        store.store_result({"domain": "example.com"}, "website", "example.com")
        raw = self._raw_results()[0]
        # A raw key needs no KDF, so there is no salt to wrap it with.
        self.assertFalse(raw.startswith(f"{store._STORE_PREFIX}:"))
        self.assertNotIn("example.com", raw)
        profile = store.export_profile("example.com")
        self.assertEqual(profile["results"]["website"], {"domain": "example.com"})

    def test_no_key_means_plaintext_and_a_warning(self):
        with mock.patch.object(display, "warn") as warn, \
             mock.patch.object(display, "info"):
            store.store_result({"domain": "example.com"}, "website", "example.com")
        self.assertEqual(self._raw_results()[0],
                         json.dumps({"domain": "example.com"}))
        self.assertEqual(warn.call_count, 1)
        self.assertIn("PLAINTEXT", warn.call_args[0][0])

    def test_the_plaintext_warning_is_not_repeated_for_every_run(self):
        with mock.patch.object(display, "warn") as warn, \
             mock.patch.object(display, "info"):
            store.store_result({"domain": "example.com"}, "website", "example.com")
            store.store_result({"domain": "example.com"}, "website", "example.com")
        self.assertEqual(warn.call_count, 1)


if __name__ == "__main__":
    unittest.main()
