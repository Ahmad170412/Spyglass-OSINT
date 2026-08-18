"""Tests for website.py's pure parsers (no network, no external tools)."""

import unittest
from unittest import mock

from helpers import imp

web = imp("website")


class Murmur3Test(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(web._murmur3_32(b""), 0)
        self.assertEqual(web._murmur3_32(b"hello"), 613153351)

    def test_seed_changes_hash(self):
        self.assertNotEqual(web._murmur3_32(b"hello", 0), web._murmur3_32(b"hello", 42))


class ParseHeadersTest(unittest.TestCase):
    def test_final_block_wins(self):
        raw = (
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://x.com/\r\n\r\n"
            "HTTP/2 200 \r\nServer: nginx\r\nContent-Type: text/html\r\n"
        )
        headers = web._parse_headers_block(raw)
        self.assertEqual(headers["server"], "nginx")
        self.assertEqual(headers["content-type"], "text/html")
        self.assertNotIn("location", headers)


class AnalyzeHeadersTest(unittest.TestCase):
    def test_present_and_missing(self):
        out = web._analyze_headers({"strict-transport-security": "max-age=1", "server": "nginx"})
        self.assertEqual(out["Strict-Transport-Security"], "max-age=1")
        self.assertEqual(out["Content-Security-Policy"], "missing")
        self.assertEqual(out["X-Frame-Options"], "missing")


class CspDomainsTest(unittest.TestCase):
    def test_domains_extracted_and_noise_removed(self):
        csp = "default-src 'self'; script-src https://cdn.example.com https://*.other.io; img-src data: 'self'"
        domains = web._extract_csp_domains(csp)
        self.assertIn("cdn.example.com", domains)
        self.assertIn("other.io", domains)
        self.assertNotIn("self", domains)
        self.assertNotIn("data", domains)


class CookiesTest(unittest.TestCase):
    def test_flags_parsed(self):
        out = web._analyze_cookies({
            "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax\ntrack=x\n"
        })
        self.assertTrue(any("session" in c and "secure=yes" in c and "httponly=yes" in c for c in out))
        self.assertTrue(any("track" in c and "secure=no" in c for c in out))


class TechnologiesTest(unittest.TestCase):
    def test_headers_and_body(self):
        headers = {"server": "nginx", "x-powered-by": "PHP/8.2"}
        body = '<html><head></head><body><script src="/wp-content/themes/x/main.js"></script></body></html>'
        tech = web._detect_technologies(headers, body)
        self.assertIn("Nginx", tech)
        self.assertIn("PHP", tech)
        self.assertIn("WordPress", tech)

    def test_generator_meta(self):
        body = '<meta name="generator" content="WordPress 6.4">'
        tech = web._detect_technologies({}, body)
        self.assertTrue(any(t.startswith("Generator:") for t in tech))


class CertCnTest(unittest.TestCase):
    def test_common_name_extracted(self):
        cert = {"subject": ((("commonName", "example.com"),), (("organizationName", "Acme"),))}
        self.assertEqual(web._cert_cn(cert, "subject"), "example.com")

    def test_missing_field(self):
        self.assertEqual(web._cert_cn({}, "subject"), "")


class RobotsTest(unittest.TestCase):
    def test_directives_parsed(self):
        body = "User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://x.com/sitemap.xml\n"
        out = web._parse_robots(body)
        self.assertIn("Disallow: /admin", out)
        self.assertIn("Sitemap: https://x.com/sitemap.xml", out)


class SitemapTest(unittest.TestCase):
    def test_locs_extracted(self):
        xml = '<?xml version="1.0"?><urlset><url><loc>https://x.com/a</loc></url><url><loc>https://x.com/b</loc></url></urlset>'
        self.assertEqual(web._parse_sitemap(xml), ["https://x.com/a", "https://x.com/b"])


class JsEndpointsTest(unittest.TestCase):
    def test_paths_and_urls(self):
        js = 'fetch("/api/v1/users"); const u = "https://cdn.x.com/assets/app.js"; x = "/graphql"'
        out = web._extract_js_endpoints(js)
        self.assertIn("/api/v1/users", out)
        self.assertIn("https://cdn.x.com/assets/app.js", out)
        self.assertIn("/graphql", out)

    def test_interesting_strings(self):
        js = 'const aws_access_key_id = "AKIA1234567890ABCDEF"; access_token="sk-live-abcdefghijklmnop"'
        out = web._extract_js_interesting(js)
        self.assertTrue(any("AKIA" in s for s in out))
        self.assertTrue(any("sk-live" in s for s in out))


class JsFilesTest(unittest.TestCase):
    def test_same_origin_only(self):
        body = (
            '<script src="/static/app.js"></script>'
            '<script src="https://evil.com/x.js"></script>'
            '<script src="//cdn.x.com/a.js"></script>'
        )
        urls = web._js_files(body, "x.com")
        self.assertIn("https://x.com/static/app.js", urls)
        self.assertIn("https://cdn.x.com/a.js", urls)
        self.assertNotIn("https://evil.com/x.js", urls)


class SpfTest(unittest.TestCase):
    def test_all_mechanism(self):
        self.assertEqual(web._spf_all("v=spf1 include:_spf.google.com -all"), "strict")
        self.assertEqual(web._spf_all("v=spf1 mx ~all"), "softfail")
        self.assertEqual(web._spf_all("v=spf1 a"), "missing")

    def test_includes(self):
        inc = web._spf_includes("v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all")
        self.assertIn("spf.protection.outlook.com", inc)
        self.assertIn("_spf.google.com", inc)


class ExposureChecksTest(unittest.TestCase):
    def test_paths_are_well_formed(self):
        for path in web._EXPOSURE_PATHS:
            self.assertTrue(path.startswith("/"))
            self.assertNotIn(" ", path)


class CertSpotterTest(unittest.TestCase):
    def test_filters_to_target_domain(self):
        data = [{"dns_names": ["example.com", "www.example.com",
                               "example.edu", "*.cdn.example.com"]}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._certspotter_subs("example.com")
        self.assertEqual(subs, {"example.com", "www.example.com", "cdn.example.com"})

    def test_non_json_response(self):
        with mock.patch.object(web, "_http_json", return_value=None):
            self.assertEqual(web._certspotter_subs("example.com"), set())

    def test_skips_non_dict_entries(self):
        data = [{"dns_names": ["www.example.com"]}, "garbage",
                {"dns_names": ["cdn.example.com"]}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._certspotter_subs("example.com")
        self.assertEqual(subs, {"www.example.com", "cdn.example.com"})


class CrtSubsTest(unittest.TestCase):
    def test_multiline_name_value(self):
        data = [{"name_value": "example.com\n*.example.com\nwww.example.com\nother.org"}]
        with mock.patch.object(web, "_http_json", return_value=data):
            subs = web._crt_subs("example.com")
        self.assertEqual(subs, {"example.com", "www.example.com"})

    def test_skips_non_dict_entries(self):
        data = [{"name_value": "www.example.com"}, "garbage"]
        with mock.patch.object(web, "_http_json", return_value=data):
            self.assertEqual(web._crt_subs("example.com"), {"www.example.com"})


class ParseHeadersMultiCookieTest(unittest.TestCase):
    def test_multiple_set_cookie_preserved(self):
        raw = (
            "HTTP/2 200\r\n"
            "Set-Cookie: a=1; Path=/\r\n"
            "Set-Cookie: b=2; HttpOnly\r\n"
            "Content-Type: text/html\r\n"
        )
        headers = web._parse_headers_block(raw)
        self.assertEqual(headers["set-cookie"], "a=1; Path=/\nb=2; HttpOnly")
        self.assertEqual(headers["content-type"], "text/html")


class LooksLikeImageTest(unittest.TestCase):
    def test_common_magic_bytes(self):
        self.assertTrue(web._looks_like_image(b"\x89PNG\r\n\x1a\n" + b"x" * 8))
        self.assertTrue(web._looks_like_image(b"\xff\xd8\xff\xe0" + b"x" * 8))
        self.assertTrue(web._looks_like_image(b"\x00\x00\x01\x00" + b"x" * 8))
        self.assertTrue(web._looks_like_image(b"GIF89a" + b"x" * 8))
        self.assertTrue(web._looks_like_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\">"))

    def test_rejects_html_and_text(self):
        self.assertFalse(web._looks_like_image(b"<html><body>404</body></html>"))
        self.assertFalse(web._looks_like_image(b"<!DOCTYPE html>"))
        self.assertFalse(web._looks_like_image(b"not an image at all"))


class FaviconTest(unittest.TestCase):
    def test_rejects_html_body(self):
        with mock.patch.object(web, "_http_bytes", return_value=b"<html><body>404</body></html>"):
            self.assertEqual(web._favicon("x.com", "<html></html>"), {})

    def test_accepts_png(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        with mock.patch.object(web, "_http_bytes", return_value=png):
            out = web._favicon("x.com", "<html></html>")
        self.assertIn("mmh3", out)
        self.assertIn("sha256", out)


class ExposureChecksTest(unittest.TestCase):
    def test_status_filter_no_redirect_false_positives(self):
        base = "https://x.com"
        codes = {
            base + "/.env": 200,
            base + "/.git/config": 301,
            base + "/.DS_Store": 404,
        }

        def fake_status(url, timeout=10, follow=True):
            self.assertFalse(follow)  # exposure checks must not follow redirects
            return codes.get(url, 404)

        with mock.patch.object(web, "_http_status", side_effect=fake_status):
            out = web._exposure_checks("x.com")
        self.assertTrue(any("/.env (200)" in x for x in out))
        self.assertTrue(any("/.git/config (301)" in x for x in out))
        self.assertFalse(any("/.DS_Store" in x for x in out))


class WaybackCdxTest(unittest.TestCase):
    def test_parses_rows_and_filters_hosts(self):
        data = [
            ["timestamp", "original", "statuscode"],
            ["20200101", "https://example.com/", "200"],
            ["20210101", "https://www.example.com/x", "200"],
            ["20220101", "https://other.com/", "200"],
        ]
        with mock.patch.object(web, "_http_json", return_value=data):
            out = web._wayback_cdx("example.com")
        self.assertEqual(out["first"], "20200101")
        self.assertEqual(out["last"], "20220101")
        self.assertEqual(out["count"], 3)
        self.assertIn("example.com", out["subs"])
        self.assertIn("www.example.com", out["subs"])
        self.assertNotIn("other.com", out["subs"])


class MemoizationTest(unittest.TestCase):
    def test_dig_short_cached_per_run(self):
        out = mock.Mock(returncode=0, stdout="1.2.3.4\n")
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_sh", return_value=out) as sh:
            web._reset_caches()
            self.assertEqual(web._dig_short("x.com", "A"), "1.2.3.4")
            self.assertEqual(web._dig_short("x.com", "A"), "1.2.3.4")
            self.assertEqual(sh.call_count, 1)

    def test_dig_short_different_args_not_cached(self):
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_sh",
                               return_value=mock.Mock(returncode=0, stdout="x\n")) as sh:
            web._reset_caches()
            web._dig_short("x.com", "A")
            web._dig_short("x.com", "AAAA")
            self.assertEqual(sh.call_count, 2)

    def test_http_body_cached_per_run(self):
        out = mock.Mock(returncode=0, stdout="<html>hi</html>")
        with mock.patch.object(web, "_CURL", "/usr/bin/curl"), \
             mock.patch.object(web, "_sh", return_value=out) as sh:
            web._reset_caches()
            self.assertEqual(web._http_body("https://x.com"), "<html>hi</html>")
            self.assertEqual(web._http_body("https://x.com"), "<html>hi</html>")
            self.assertEqual(sh.call_count, 1)


class PhaseWhoisTest(unittest.TestCase):
    def test_registered_follows_referral(self):
        thin = "refer: whois.verisign-grs.com\ndomain: COM\n"
        full = "Domain Name: GITHUB.COM\nRegistrar: MarkMonitor Inc.\n"
        with mock.patch.object(web, "_check_tool", return_value=True), \
             mock.patch.object(web, "_run", side_effect=[thin, full]):
            out = web._phase_whois("github.com")
        self.assertEqual(out["whois"]["Domain"], "GITHUB.COM")
        self.assertEqual(out["whois"]["Registrar"], "MarkMonitor Inc.")

    def test_unregistered_not_tld_data(self):
        thin = ("refer: whois.verisign-grs.com\n"
                "domain: COM\norganisation: VeriSign Global Registry Services\n")
        full = 'No match for domain "X.COM".\n'
        with mock.patch.object(web, "_check_tool", return_value=True), \
             mock.patch.object(web, "_run", side_effect=[thin, full]) as run:
            out = web._phase_whois("x.com")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(out["whois"]["Status"], "unregistered (no registry record)")
        self.assertNotIn("Organization", out["whois"])
        self.assertNotIn("Domain", out["whois"])


class PhaseDnsTest(unittest.TestCase):
    def test_collects_ips_and_records(self):
        def fake_dig(*args, **kwargs):
            return {"A": "1.2.3.4", "AAAA": "", "MX": "10 mail.x.com."}.get(args[1], "")
        with mock.patch.object(web, "_DIG", "/usr/bin/dig"), \
             mock.patch.object(web, "_dig_short", side_effect=fake_dig), \
             mock.patch.object(web, "_dns_email_security", return_value=None), \
             mock.patch.object(web, "_is_wildcard", return_value=(False, "")), \
             mock.patch.object(web, "_axfr", return_value=[]):
            out = web._phase_dns("x.com")
        self.assertEqual(out["dns_records"]["A"], "1.2.3.4")
        self.assertEqual(out["_ips"], {"1.2.3.4"})


if __name__ == "__main__":
    unittest.main()
