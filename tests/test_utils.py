"""Tests for utils.py: domain parsing, entity extraction, safe filenames."""

import unittest
from unittest import mock

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


class PageIsRealTest(unittest.TestCase):
    """Body inspection behind _verify.

    Every fixture here is modelled on a response that was observed returning
    HTTP 200 for a profile that does not exist.
    """

    @staticmethod
    def _body(text, pad=0):
        return text + ("x" * pad)

    def test_real_page_passes(self):
        body = self._body("<html><head><title>Jane Doe</title></head>"
                          "<body>profile</body></html>", pad=3000)
        ok, why = utils._page_is_real(body, 200)
        self.assertTrue(ok)
        self.assertEqual(why, "ok")

    def test_challenge_titles_are_rejected(self):
        for title in ("Just a moment...", "Security Verification",
                      "Client Challenge", "Attention Required! | Cloudflare",
                      "Checking your browser before accessing",
                      "403 Forbidden", "Are you a robot?"):
            body = self._body(f"<html><head><title>{title}</title></head>"
                              "<body>real content here</body></html>", pad=3000)
            ok, why = utils._page_is_real(body, 200)
            self.assertFalse(ok, title)
            self.assertIn("challenge", why, title)

    def test_specific_challenge_body_markers_are_rejected(self):
        for marker in ("cf-browser-verification", "cf_chl_opt", "cf-turnstile",
                       "px-captcha", "ddos protection by", "enable javascript and cookies"):
            body = self._body(f"<html><body>{marker}</body></html>", pad=3000)
            ok, why = utils._page_is_real(body, 200)
            self.assertFalse(ok, marker)
            self.assertEqual(why, "bot challenge", marker)

    def test_generic_words_in_a_script_payload_do_not_reject(self):
        # Regression: a whole-body scan for "captcha" matched GitHub's own
        # feature flag "octocaptcha_origin_optimization" in the JS payload and
        # rejected every real GitHub profile as a bot challenge.
        body = self._body(
            "<html><head><title>torvalds (Linus Torvalds) - GitHub</title></head>"
            '<body><script>{"enabled_features":["octocaptcha_origin_optimization",'
            '"captcha_secret"]}</script><p>Linus Torvalds</p></body></html>', pad=3000)
        ok, why = utils._page_is_real(body, 200)
        self.assertTrue(ok, why)

    def test_not_found_rejected_from_title(self):
        body = self._body("<html><head><title>Page not found</title></head>"
                          "<body>404</body></html>", pad=3000)
        ok, why = utils._page_is_real(body, 200)
        self.assertFalse(ok)
        self.assertIn("not found", why)

    def test_not_found_phrase_in_body_alone_is_not_rejected(self):
        # Forum templates and ad scripts mention "not found" in unrelated copy;
        # matching the body would throw away genuine profiles.
        body = self._body("<html><head><title>Jane Doe</title></head>"
                          "<body>this post was not found in the archive</body></html>",
                          pad=3000)
        ok, _ = utils._page_is_real(body, 200)
        self.assertTrue(ok)

    def test_empty_spa_shell_rejected_on_size(self):
        ok, why = utils._page_is_real("<html><body></body></html>", 200)
        self.assertFalse(ok)
        self.assertIn("too small", why)

    def test_non_2xx_rejected(self):
        body = self._body("<html><title>Jane</title></html>", pad=3000)
        for code in (301, 404, 403, 500):
            ok, why = utils._page_is_real(body, code)
            if code == 301:
                self.assertTrue(ok, why)   # redirects are still followed
            else:
                self.assertFalse(ok, code)


class _FakeProc:
    """Stands in for subprocess.CompletedProcess."""

    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0
        self.stderr = ""


def _fake_curl(pages):
    """Patch subprocess.run so curl returns `pages` keyed by URL.

    ``pages`` maps a URL to ``(body, status)``. Anything unmapped 404s.
    """
    def _run(cmd, **kwargs):
        body, code = pages.get(cmd[-1], ("", 404))
        return _FakeProc(f"{body}\n{code}")
    return mock.patch.object(utils.subprocess, "run", side_effect=_run)


class VerifyTest(unittest.TestCase):
    """The network call is stubbed; only the decision logic is exercised."""

    RICH = "<html><head><title>Jane Doe</title></head><body>jane jane profile</body></html>" + "x" * 3000
    # A 610KB signup interstitial that echoes the requested slug dozens of times
    # and names a different person in its title. Counting occurrences admits it;
    # requiring the page to *state* the handle rejects it.
    INTERSTITIAL = ('<html><head><title>Signup for free to see more about Anthony'
                    "</title></head><body>" + ("@jdoe " * 400) + "</body></html>")
    # A real interstitial names itself in the <title>; that is the reliable signal.
    CHALLENGE = "<html><head><title>Just a moment...</title></head><body>checking</body></html>" + "x" * 3000
    SHELL = "<html><head><title>Bluesky</title></head><body></body></html>" + "x" * 3000

    def test_empty_input_short_circuits(self):
        self.assertEqual(utils._verify([]), set())

    def test_existing_profile_passes(self):
        with _fake_curl({"u": (self.RICH, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True), {"u"})

    def test_challenge_is_rejected(self):
        with _fake_curl({"u": (self.CHALLENGE, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True), set())

    def test_empty_shell_is_rejected(self):
        with _fake_curl({"u": ("<html></html>", 200)}):
            self.assertEqual(utils._verify(["u"], silent=True), set())

    def test_not_found_title_is_rejected(self):
        with _fake_curl({"u": ("<html><title>404 Not Found</title></html>" + "x" * 3000, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True), set())

    def test_expect_rejects_page_that_omits_the_term(self):
        with _fake_curl({"u": (self.SHELL, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jdoe"), set())

    def test_expect_rejects_a_bare_echo_of_the_term(self):
        # A Mastodon soft-404 returns 200, ~50KB, no error marker, and reproduces
        # the requested handle exactly once. A real profile names it in its title.
        echo = "<html><head><title>Mastodon</title></head><body>" \
               "@jdoe" + "x" * 4000 + "</body></html>"
        with _fake_curl({"u": (echo, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jdoe"), set())

    def test_registration_prompt_is_rejected_however_large(self):
        with _fake_curl({"u": (self.INTERSTITIAL, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jdoe"), set())

    def test_a_real_profile_titled_by_display_name_is_kept(self):
        # Regression: requiring the handle in the title rejected a real YouTube
        # profile titled "Nat - YouTube" belonging to the handle "qrxznat".
        body = ('<html><head><title>Nat - YouTube</title></head><body>'
                + ("qrxznat " * 200) + "</body></html>")
        with _fake_curl({"u": (body, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="qrxznat"), {"u"})

    def test_single_mention_is_treated_as_an_echo(self):
        once = "<html><head><title>Profile</title></head><body>jdoe" + "x" * 3000 + "</body></html>"
        with _fake_curl({"u": (once, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jdoe"), set())

    def test_expect_accepts_a_repeated_term(self):
        with _fake_curl({"u": (self.RICH, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jane"), {"u"})

    def test_expect_is_case_insensitive(self):
        body = "<html><title>JDOE</title></html>jdoe jdoe" + "x" * 3000
        with _fake_curl({"u": (body, 200)}):
            self.assertEqual(utils._verify(["u"], silent=True, expect="jdoe"), {"u"})

    def test_malformed_status_is_rejected(self):
        with _fake_curl({"u": ("body", "abc")}):
            self.assertEqual(utils._verify(["u"], silent=True), set())

    def test_rejections_tally_is_reported_to_the_caller(self):
        # Without this the filtering is invisible and a search that found six and
        # kept one looks identical to one that found a single result.
        tally = {}
        with _fake_curl({"good": (self.RICH, 200), "bad": (self.CHALLENGE, 200)}):
            utils._verify(["good", "bad"], silent=True, rejections=tally)
        self.assertEqual(sum(tally.values()), 1)
        self.assertTrue(any("challenge" in k for k in tally), tally)

    def test_rejections_are_cleared_not_accumulated_across_calls(self):
        tally = {}
        with _fake_curl({"bad": (self.CHALLENGE, 200)}):
            utils._verify(["bad"], silent=True, rejections=tally)
        first = dict(tally)
        with _fake_curl({"good": (self.RICH, 200)}):
            utils._verify(["good"], silent=True, rejections=tally)
        self.assertEqual(tally, {})

    def test_mixed_set_keeps_only_the_real_one(self):
        with _fake_curl({"good": (self.RICH, 200), "bad": (self.CHALLENGE, 200)}):
            self.assertEqual(utils._verify(["good", "bad"], silent=True), {"good"})


if __name__ == "__main__":
    unittest.main()


class VerifyRetryTest(unittest.TestCase):
    """A throttled real profile must not be recorded as a missing one."""

    def _verify_with(self, codes):
        """Feed _verify a scripted sequence of HTTP statuses, one per attempt."""
        seq = list(codes)

        def fake_run(cmd, **kw):
            code = seq.pop(0) if seq else 200
            # A real profile page is well over the body-size floor, and the
            # handle has to appear more than once to not read as an echo.
            body = ("<html><title>Nat</title>" + "filler " * 400
                    + "qrxznat qrxznat</html>") if code == 200 else "busy"
            done = mock.Mock(stdout=f"{body}\n{code}", stderr="", returncode=0)
            return done

        with mock.patch.object(utils.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(utils.time, "sleep"):
            rej = {}
            alive = utils._verify({"https://x.com/qrxznat"}, silent=True,
                               expect="qrxznat", rejections=rej)
            return alive, rej

    def test_429_then_success_keeps_the_profile(self):
        alive, rej = self._verify_with([429, 429, 200])
        self.assertEqual(alive, {"https://x.com/qrxznat"})
        self.assertEqual(rej, {})

    def test_persistent_429_is_still_rejected(self):
        alive, rej = self._verify_with([429, 429, 429])
        self.assertEqual(alive, set())
        self.assertEqual(list(rej), ["http 429"])

    def test_real_verdicts_are_not_retried(self):
        # A not-found title is the same on the second request, so only one
        # request should be made: asking again just costs time.
        alive, rej = self._verify_with([404])
        self.assertEqual(alive, set())
        self.assertEqual(list(rej), ["http 404"])
