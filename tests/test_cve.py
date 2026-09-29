"""Tests for cve.py's detection, version logic and NVD parsing (no network)."""

import os
import unittest
from unittest import mock

from helpers import imp

cve = imp("cve")


def _nvd_one(cid, sev="HIGH", score=7.5, vendor="f5", product="nginx",
             start=None, end=None, start_inc=None, end_inc=None):
    """One NVD vulnerability entry, shaped like the real API response."""
    crit = f"cpe:2.3:a:{vendor}:{product}"
    match = {"vulnerable": True, "criteria": crit + ":*:*:*:*:*:*:*:*"}
    if start:
        match["versionStartIncluding" if start_inc else "versionStartExcluding"] = start
    if end:
        match["versionEndIncluding" if end_inc else "versionEndExcluding"] = end
    return {
        "cve": {
            "id": cid,
            "published": "2017-07-13T12:29:00.000",
            "descriptions": [{"lang": "en", "value": "integer overflow in resolver"}],
            "references": [{"url": "https://example.test/a"}, {"url": "https://example.test/b"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score,
                                                        "baseSeverity": sev}}]},
            "configurations": [{"nodes": [{"cpeMatch": [match]}]}],
        }
    }


def _nwd_range(cid, vendor, product, start, end):
    """Advisory whose CPE carries an explicit inclusive range."""
    return _nvd_one(cid, vendor=vendor, product=product,
                    start=start, end=end, start_inc=True, end_inc=True)


def cve_mod():
    return cve


class DetectComponentsTest(unittest.TestCase):
    def test_server_banner_product_and_version(self):
        got = cve.detect_components({"server": "nginx/1.13.2 (Ubuntu)"})
        self.assertEqual([(c["product"], c["version"]) for c in got],
                         [("nginx", "1.13.2")])

    def test_x_powered_by_php(self):
        got = cve.detect_components({"x-powered-by": "PHP/7.4.3"})
        self.assertIn(("php", "7.4.3"), [(c["product"], c["version"]) for c in got])

    def test_jenkins_dedicated_header(self):
        got = cve.detect_components({"x-jenkins": "2.289.1"})
        self.assertIn(("jenkins", "2.289.1"), [(c["product"], c["version"]) for c in got])

    def test_wordpress_generator_in_body(self):
        body = '<meta name="generator" content="WordPress 6.0.1">'
        got = cve.detect_components({}, body)
        self.assertIn(("wordpress", "6.0.1"), [(c["product"], c["version"]) for c in got])

    def test_jquery_from_asset_filename(self):
        body = '<script src="/static/jquery-3.4.1.min.js"></script>'
        got = cve.detect_components({}, body)
        self.assertIn(("jquery", "3.4.1"), [(c["product"], c["version"]) for c in got])

    def test_distribution_suffix_is_stripped(self):
        got = cve.detect_components({"server": "nginx/1.18.0-0ubuntu1"})
        self.assertEqual(got[0]["version"], "1.18.0")

    def test_multiple_components_are_all_found(self):
        got = cve.detect_components({"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2"})
        self.assertEqual(sorted(c["product"] for c in got), ["nginx", "php"])

    def test_product_without_a_version_is_not_reported(self):
        self.assertEqual(cve.detect_components({"server": "cloudflare"}), [])

    def test_empty_inputs(self):
        self.assertEqual(cve.detect_components({}, ""), [])
        self.assertEqual(cve.detect_components(None, None), [])

    def test_evidence_is_recorded(self):
        got = cve.detect_components({"server": "nginx/1.13.2 (Ubuntu)"})
        self.assertIn("nginx", got[0]["evidence"])
        self.assertEqual(got[0]["source"], "header:server")


class CleanVersionTest(unittest.TestCase):
    def test_strips_v_prefix_and_suffixes(self):
        self.assertEqual(cve._clean_version("v1.2.3"), "1.2.3")
        self.assertEqual(cve._clean_version("1.2.3-4ubuntu2"), "1.2.3")
        self.assertEqual(cve._clean_version("1.2.3+deb11u1"), "1.2.3")

    def test_rejects_non_numeric(self):
        self.assertEqual(cve._clean_version("all"), "")
        self.assertEqual(cve._clean_version(""), "")


class VersionInRangeTest(unittest.TestCase):
    def test_inclusive_and_exclusive_bounds(self):
        self.assertTrue(cve.version_in_range("1.13.1", "1.13.0", True, "1.13.2", False))
        self.assertFalse(cve.version_in_range("1.13.2", "1.13.0", True, "1.13.2", False))
        self.assertFalse(cve.version_in_range("1.13.3", "1.13.0", True, "1.13.2", False))
        self.assertFalse(cve.version_in_range("1.12.9", "1.13.0", True, "1.13.2", False))

    def test_unbounded_means_every_version(self):
        self.assertTrue(cve.version_in_range("2.4.49", None, False, None, False))

    def test_empty_version_is_never_in_range(self):
        self.assertFalse(cve.version_in_range("", None, False, None, False))

    def test_version_key_pads_and_orders(self):
        self.assertEqual(cve._version_key("1.2"), cve._version_key("1.2.0"))
        self.assertLess(cve._version_key("1.9.0"), cve._version_key("1.10.0"))


class CpeTest(unittest.TestCase):
    def test_vendor_spellings_expand_to_cpes(self):
        cpes = cve._cpes_for("nginx", "1.13.2")
        self.assertEqual(cpes[0], "cpe:2.3:a:f5:nginx:1.13.2")
        self.assertIn("cpe:2.3:a:igor_sysoev:nginx:1.13.2", cpes)

    def test_marketing_name_differs_from_cpe_product(self):
        self.assertEqual(cve._cpes_for("apache", "2.4.49")[0],
                         "cpe:2.3:a:apache:http_server:2.4.49")

    def test_wildcard_fallback_has_no_version(self):
        self.assertEqual(cve._cpe_wildcards("php")[0], "cpe:2.3:a:php:php")

    def test_unknown_product_yields_no_cpes(self):
        self.assertEqual(cve._cpes_for("nope", "1.0"), [])


class ParseNvdTest(unittest.TestCase):
    def test_core_fields(self):
        payload = {"vulnerabilities": [_nvd_one("CVE-2017-7529", start="0.5.6",
                                                end="1.13.2", start_inc=True, end_inc=True)]}
        c = cve._parse_nvd(payload, "nginx", "1.13.2", "header:server", 5, "f5")[0]
        self.assertEqual(c["id"], "CVE-2017-7529")
        self.assertEqual(c["severity"], "HIGH")
        self.assertEqual(c["score"], 7.5)
        self.assertEqual(c["published"], "2017-07-13")
        self.assertEqual(len(c["references"]), 2)

    def test_affected_range_is_surfaced(self):
        payload = {"vulnerabilities": [_nvd_one("CVE-1", start="0.5.6", end="1.13.2",
                                                start_inc=True, end_inc=True)]}
        c = cve._parse_nvd(payload, "nginx", "1.13.2", "", 5, "f5")[0]
        self.assertIn(">= 0.5.6, <= 1.13.2", c["affected"])

    def test_open_ended_range_renders_as_inequality(self):
        payload = {"vulnerabilities": [_nvd_one("CVE-2", vendor="php", product="php",
                                                end="7.4.24")]}
        c = cve._parse_nvd(payload, "php", "7.4.3", "", 5, "php")[0]
        self.assertEqual(c["affected"], ["< 7.4.24"])

    def test_exact_version_criterion_is_not_reported_as_all_versions(self):
        entry = _nvd_one("CVE-E", vendor="apache", product="http_server")
        entry["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"] = \
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        c = cve._parse_nvd({"vulnerabilities": [entry]}, "apache", "2.4.49", "", 5, "apache")[0]
        self.assertEqual(c["affected"], ["2.4.49"])

    def test_range_free_match_reads_as_all_versions(self):
        payload = {"vulnerabilities": [_nvd_one("CVE-3", vendor="php", product="php")]}
        c = cve._parse_nvd(payload, "php", "7.4.3", "", 5, "php")[0]
        self.assertEqual(c["affected"], ["all versions"])

    def test_range_for_a_different_product_is_dropped_not_attributed(self):
        payload = {"vulnerabilities": [_nvd_one("CVE-6", vendor="f5", product="nginx",
                                                end="1.13.2")]}
        # A php query must not inherit an nginx advisory.
        self.assertEqual(cve._parse_nvd(payload, "php", "7.4.3", "", 5, "php"), [])

    def test_entries_missing_an_id_are_dropped(self):
        payload = {"vulnerabilities": [{"cve": {}}, _nvd_one("CVE-9")]}
        out = cve._parse_nvd(payload, "nginx", "1.13.2", "", 5, "f5")
        self.assertEqual([c["id"] for c in out], ["CVE-9"])

    def test_cvss_v2_without_severity_gets_a_derived_label(self):
        entry = _nvd_one("CVE-4")
        entry["cve"]["metrics"] = {"cvssMetricV2": [{"cvssData": {"baseScore": 9.8}}]}
        c = cve._parse_nvd({"vulnerabilities": [entry]}, "nginx", "1.13.2", "", 5, "f5")[0]
        self.assertEqual(c["severity"], "CRITICAL")

    def test_no_metrics_leaves_severity_blank(self):
        entry = _nvd_one("CVE-5")
        entry["cve"]["metrics"] = {}
        c = cve._parse_nvd({"vulnerabilities": [entry]}, "nginx", "1.13.2", "", 5, "f5")[0]
        self.assertEqual(c["severity"], "")
        self.assertIsNone(c["score"])

    def test_cap_limits_results(self):
        payload = {"vulnerabilities": [_nvd_one(f"CVE-{i}") for i in range(20)]}
        out = cve._parse_nvd(payload, "nginx", "1.13.2", "", 3, "f5")
        self.assertEqual(len(out), 3)


class CheckTest(unittest.TestCase):
    def test_no_queryable_components_reports_cleanly(self):
        r = cve.check([{"product": "nginx", "version": ""}])
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["cve_count"], 0)
        self.assertEqual(r["checked"], 0)
        self.assertIn("note", r)

    def test_curl_missing_is_unavailable_not_a_crash(self):
        with mock.patch.object(cve, "_CURL", None):
            r = cve.check([{"product": "nginx", "version": "1.13.2"}])
        self.assertEqual(r["status"], "unavailable")

    def test_server_side_components_are_queried_before_frontend_ones(self):
        comps = [{"product": "jquery", "version": "3.4.1"},
                 {"product": "nginx", "version": "1.13.2"}]
        seen = []

        def _fake(params, key=None, timeout=45, retries=2):
            seen.append(params["virtualMatchString"])
            return {"vulnerabilities": []}

        with mock.patch.object(cve, "_nvd_get", side_effect=_fake):
            cve.check(comps, cap=1)
        self.assertIn("f5:nginx:1.13.2", seen[0])

    def test_cap_limits_how_many_products_are_queried(self):
        comps = [{"product": p, "version": "1.0"} for p in ("nginx", "apache", "php")]
        with mock.patch.object(cve, "_nvd_get", return_value={"vulnerabilities": []}):
            r = cve.check(comps, cap=1)
        self.assertEqual(r["checked"], 1)
        self.assertEqual(sorted(r["skipped"]), ["apache", "php"])

    def test_results_are_sorted_worst_severity_first(self):
        def _fake(params, key=None, timeout=45, retries=2):
            return {"vulnerabilities": [
                _nvd_one("CVE-LOW", "LOW", 2.0),
                _nvd_one("CVE-CRIT", "CRITICAL", 9.8),
                _nvd_one("CVE-MED", "MEDIUM", 5.0),
            ]}

        comps = [{"product": "nginx", "version": "1.13.2"}]
        with mock.patch.object(cve, "_nvd_get", side_effect=_fake):
            r = cve.check(comps, cap=1)
        self.assertEqual([c["id"] for c in r["cves"]],
                         ["CVE-CRIT", "CVE-MED", "CVE-LOW"])

    def test_request_failure_is_recorded_not_raised(self):
        comps = [{"product": "nginx", "version": "1.13.2"}]
        with mock.patch.object(cve, "_nvd_get", return_value=None):
            r = cve.check(comps, cap=1)
        self.assertEqual(r["cve_count"], 0)
        self.assertTrue(r["errors"])

    def test_scan_attaches_detection(self):
        with mock.patch.object(cve, "check", return_value={"status": "ok", "cve_count": 0,
                                                          "cves": []}):
            r = cve.scan({"server": "nginx/1.13.2"})
        self.assertEqual(r["detected"][0]["product"], "nginx")


class CveAffectsTest(unittest.TestCase):
    """The range check that stops NVD's own mismatches becoming CVE claims."""

    def test_version_inside_the_range_is_affected(self):
        cve = _nvd_one("CVE-1", vendor="f5", product="nginx",
                       start="0.5.6", end="1.13.2", start_inc=True, end_inc=True)["cve"]
        self.assertTrue(cve_mod()._cve_affects(cve, "f5", "nginx", "1.13.2"))

    def test_version_past_the_range_is_not_affected(self):
        cve = _nvd_one("CVE-2", vendor="f5", product="nginx",
                       start="0.1.0", end="0.8.22", start_inc=True, end_inc=True)["cve"]
        self.assertFalse(cve_mod()._cve_affects(cve, "f5", "nginx", "1.31.3"))

    def test_exact_version_criterion_matches_only_that_version(self):
        cve = _nvd_one("CVE-3", vendor="apache", product="http_server")["cve"]
        crit = cve["configurations"][0]["nodes"][0]["cpeMatch"][0]
        crit["criteria"] = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        self.assertTrue(cve_mod()._cve_affects(cve, "apache", "http_server", "2.4.49"))
        self.assertFalse(cve_mod()._cve_affects(cve, "apache", "http_server", "2.4.50"))

    def test_unbounded_wildcard_is_a_product_wide_advisory(self):
        cve = _nvd_one("CVE-4", vendor="php", product="php")["cve"]
        self.assertTrue(cve_mod()._cve_affects(cve, "php", "php", "7.4.3"))

    def test_matching_a_different_product_is_never_affected(self):
        cve = _nvd_one("CVE-5", vendor="f5", product="nginx", end="1.13.2")["cve"]
        self.assertFalse(cve_mod()._cve_affects(cve, "f5", "nginx", "1.31.3"))

    def test_empty_version_is_never_affected(self):
        cve = _nvd_one("CVE-6")["cve"]
        self.assertFalse(cve_mod()._cve_affects(cve, "f5", "nginx", ""))


class ParseNvdFilteringTest(unittest.TestCase):
    def test_out_of_range_advisories_are_dropped(self):
        # The real regression: a query for a current nginx returned advisories
        # whose ranges end decades earlier.
        payload = {"vulnerabilities": [
            _nwd_range("CVE-OLD", "f5", "nginx", "0.1.0", "0.8.22"),
            _nwd_range("CVE-HIT", "f5", "nginx", "1.0.0", "1.31.3"),
        ]}
        out = cve._parse_nvd(payload, "nginx", "1.31.3", "", 10, "f5")
        self.assertEqual([c["id"] for c in out], ["CVE-HIT"])

    def test_cap_applies_after_filtering(self):
        payload = {"vulnerabilities": [
            _nwd_range(f"CVE-{i}", "f5", "nginx", "1.0.0", "1.31.3") for i in range(9)
        ] + [_nwd_range("CVE-OLD", "f5", "nginx", "0.1.0", "0.8.22")]}
        out = cve._parse_nvd(payload, "nginx", "1.31.3", "", 3, "f5")
        self.assertEqual(len(out), 3)
        self.assertNotIn("CVE-OLD", [c["id"] for c in out])

    def test_wildcard_cpes_are_never_queried(self):
        self.assertEqual(cve._cpes_for("nginx", "1.31.3"),
                         ["cpe:2.3:a:f5:nginx:1.31.3",
                          "cpe:2.3:a:igor_sysoev:nginx:1.31.3"])
        for cpe in cve._cpes_for("nginx", "1.31.3"):
            self.assertNotIn(":*:*:*", cpe)


class NvdApiKeyTest(unittest.TestCase):
    """``NVD_API_KEY`` lifts the rate limit, and the docs promise it works.

    It used to be reachable only as a ``key`` argument, and the CLI never
    supplied one — only the web console wired up the environment variable. So on
    the command line the documented variable silently did nothing and every
    lookup ran at the anonymous 5-per-30s ceiling.
    """

    def _check_with_env(self, env_value, **kwargs):
        seen = []

        def _fake(params, key=None, timeout=45, retries=2):
            seen.append(key)
            return {"vulnerabilities": []}

        env = {} if env_value is None else {"NVD_API_KEY": env_value}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(cve, "_nvd_get", side_effect=_fake):
            r = cve.check([{"product": "nginx", "version": "1.13.2"}], cap=1, **kwargs)
        return r, seen

    def test_env_var_supplies_the_key(self):
        r, seen = self._check_with_env("env-key")
        self.assertIn("env-key", seen)
        self.assertTrue(r["keyed"])

    def test_explicit_key_wins_over_env(self):
        _, seen = self._check_with_env("env-key", key="flag-key")
        self.assertIn("flag-key", seen)
        self.assertNotIn("env-key", seen)

    def test_unset_env_leaves_it_keyless(self):
        r, seen = self._check_with_env(None)
        # nginx resolves to two vendor spellings, so more than one query is made.
        self.assertTrue(seen)
        self.assertEqual(set(seen), {None})
        self.assertFalse(r["keyed"])

    def test_empty_env_string_is_not_treated_as_a_key(self):
        r, seen = self._check_with_env("")
        self.assertTrue(seen)
        self.assertEqual(set(seen), {None})
        self.assertFalse(r["keyed"])


if __name__ == "__main__":
    unittest.main()
