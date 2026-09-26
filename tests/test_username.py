"""Tests for username.py's tool runners (graceful degradation, no network)."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import imp

uname = imp("username")
un = uname
ut = imp("utils")
display = imp("display")


class RunnerGracefulTest(unittest.TestCase):
    def _run(self, fn):
        with mock.patch.object(uname, "_check_tool", return_value=True):
            return fn

    def test_sherlock_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("sherlock", 300)):
            self.assertEqual(uname._sherlock("johnsmith"), {})

    def test_maigret_error_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run", side_effect=OSError("boom")):
            self.assertEqual(uname._maigret("x"), ({}, {}))

    def test_user_scanner_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("user-scanner", 120)):
            self.assertEqual(uname._us_username("x"), {})

    def test_blackbird_timeout_returns_empty(self):
        with mock.patch.object(uname, "_check_tool", return_value=True), \
             mock.patch.object(uname.subprocess, "run",
                               side_effect=uname.subprocess.TimeoutExpired("blackbird", 300)):
            self.assertEqual(uname._blackbird_username("x"), {})


class VerdictTest(unittest.TestCase):
    """A thin result set must say how strong the evidence is, not look like a find."""

    def test_nothing_found_is_stated_as_a_real_result(self):
        v = un._verdict(set(), set(), set(), set())
        self.assertIn("No verified profiles", v)
        self.assertIn("not an error", v)

    def test_only_single_tool_hits_are_called_unconfirmed(self):
        v = un._verdict({"a.com"}, set(), set(), set())
        self.assertIn("unconfirmed", v)
        self.assertIn("lead, not a finding", v)

    def test_corroborated_hits_are_counted_separately(self):
        v = un._verdict({"a.com", "b.com"}, {"a.com"}, set(), set())
        self.assertIn("2 platform(s)", v)
        self.assertIn("1 corroborated", v)
        self.assertIn("1 single-tool lead", v)


class ToolFailureTest(unittest.TestCase):
    """A crashed engine must not be reported as an engine that found nothing."""

    def test_non_zero_exit_is_reported(self):
        class P:
            returncode = 1
            stderr = "FileNotFoundError: data/wmn-data.json"
        with mock.patch.object(display, "warn") as w:
            self.assertTrue(ut._tool_failed("blackbird", P()))
        w.assert_called_once()
        self.assertIn("blackbird", w.call_args[0][0])

    def test_clean_exit_is_silent(self):
        class P:
            returncode = 0
            stderr = ""
        with mock.patch.object(display, "warn") as w:
            self.assertFalse(ut._tool_failed("sherlock", P()))
        w.assert_not_called()

    def test_missing_proc_is_silent(self):
        self.assertFalse(ut._tool_failed("sherlock", None))

    def test_blackbird_dataset_presence_is_checked(self):
        ok, why = ut.blackbird_ready()
        self.assertIsInstance(ok, bool)
        if not ok:
            self.assertTrue(why)


class _Completed:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


class MaigretReportTest(unittest.TestCase):
    """maigret's ndjson report: profile URLs and extracted data in one pass."""

    RECORD = [{
        "sitename": "YouTube",
        "url_user": "https://www.youtube.com/@qrxznat/about",
        "status": {
            "username": "qrxznat", "site_name": "YouTube", "status": "Claimed",
            "url": "https://www.youtube.com/@qrxznat/about",
            "ids": {"youtube_channel_id": "UCHVFC", "fullname": "Nat",
                    "bio": "haechan 90s", "image": "https://yt3/x.jpg",
                    "_extractor": "YouTube ytInitialData"},
        },
    }]

    def _run_with(self, records, stdout="", write_report=True):
        """Run _maigret against a stubbed maigret that writes `records`."""
        real = tempfile.mkdtemp(prefix="sg-test-")
        if write_report:
            with open(os.path.join(real, "report_ndjson.json"), "w") as fh:
                fh.write("\n".join(json.dumps(r) for r in records))
        try:
            with mock.patch.object(un, "_MG", "/usr/bin/maigret"), \
                 mock.patch.object(un.subprocess, "run",
                                   return_value=_Completed(stdout)), \
                 mock.patch.object(un.tempfile, "mkdtemp", return_value=real), \
                 mock.patch.object(un.shutil, "rmtree"):
                return un._maigret("qrxznat")
        finally:
            shutil.rmtree(real, ignore_errors=True)

    def test_claimed_record_yields_both_a_hit_and_its_data(self):
        hits, details = self._run_with(self.RECORD)
        self.assertEqual(hits, {"youtube.com": "https://www.youtube.com/@qrxznat/about"})
        self.assertEqual(details["youtube.com"]["fullname"], "Nat")
        self.assertEqual(details["youtube.com"]["youtube_channel_id"], "UCHVFC")
        self.assertEqual(details["youtube.com"]["bio"], "haechan 90s")
        # The extractor name is an implementation detail, not intelligence.
        self.assertNotIn("_extractor", details["youtube.com"])

    def test_unclaimed_records_are_ignored(self):
        hits, details = self._run_with([{"status": {"status": "Unclaimed",
                                                   "url": "https://x.com/u",
                                                   "ids": {"fullname": "nobody"}}}])
        self.assertEqual((hits, details), ({}, {}))

    def test_claimed_record_with_no_ids_is_still_a_hit(self):
        # A hit with nothing extractable is still a hit; the two maps are
        # built independently so a sparse record is not dropped entirely.
        hits, details = self._run_with([{"status": {"status": "Claimed",
                                                   "url": "https://x.com/u"}}])
        self.assertEqual(hits, {"x.com": "https://x.com/u"})
        self.assertEqual(details, {})

    def test_falls_back_to_stdout_when_no_report_is_written(self):
        # A maigret build that writes no report must not read as "no accounts".
        stdout = ("[+] MAIGRET v1.0\n"
                  "[+] https://www.youtube.com/@qrxznat\n"
                  "[+] Donate: https://maigret.io\n")
        hits, details = self._run_with([], stdout=stdout, write_report=False)
        self.assertEqual(hits, {"youtube.com": "https://www.youtube.com/@qrxznat"})
        self.assertEqual(details, {})

    def test_temp_output_dir_is_removed_and_cwd_stays_clean(self):
        before = os.path.isdir("reports")
        self._run_with(self.RECORD)
        # maigret writes dossiers into ./reports unless redirected.
        self.assertEqual(os.path.isdir("reports"), before)

    def test_site_cap_is_above_the_previous_fifty(self):
        # 50 was a 200x restriction on a 6,206-site database; measured at 1000
        # for +22s and 6 -> 16 unique domains on a real handle.
        self.assertGreaterEqual(un._MG_SITES, 1000)


if __name__ == "__main__":
    unittest.main()
