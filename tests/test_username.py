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
            self.assertEqual(uname._maigret("x"), {})

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


class MaigretDetailsTest(unittest.TestCase):
    """maigret's nested status.ids payload — the richest output in the toolchain."""

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

    def _run_with(self, records):
        """Run _maigret_details against a stubbed maigret that writes `records`."""
        real = tempfile.mkdtemp(prefix="sg-test-")
        with open(os.path.join(real, "report_ndjson.json"), "w") as fh:
            fh.write("\n".join(json.dumps(r) for r in records))
        try:
            with mock.patch.object(un, "_MG", "/usr/bin/maigret"), \
                 mock.patch.object(un.subprocess, "run",
                                   return_value=_Completed("")), \
                 mock.patch.object(un.tempfile, "mkdtemp", return_value=real), \
                 mock.patch.object(un.shutil, "rmtree"):
                return un._maigret_details("qrxznat")
        finally:
            shutil.rmtree(real, ignore_errors=True)

    def test_claimed_records_yield_usable_data(self):
        out = self._run_with(self.RECORD)
        self.assertIn("youtube.com", out)
        self.assertEqual(out["youtube.com"]["fullname"], "Nat")
        self.assertEqual(out["youtube.com"]["youtube_channel_id"], "UCHVFC")
        self.assertEqual(out["youtube.com"]["bio"], "haechan 90s")
        # The extractor name is an implementation detail, not intelligence.
        self.assertNotIn("_extractor", out["youtube.com"])

    def test_unclaimed_records_are_ignored(self):
        out = self._run_with([{"status": {"status": "Unclaimed",
                                          "url": "https://x.com/u",
                                          "ids": {"fullname": "nobody"}}}])
        self.assertEqual(out, {})

    def test_record_without_ids_yields_nothing(self):
        self.assertEqual(self._run_with([{"status": {"status": "Claimed",
                                                     "url": "https://x.com/u"}}]), {})

    def test_temp_output_dir_is_removed_and_cwd_stays_clean(self):
        before = os.path.isdir("reports")
        self._run_with(self.RECORD)
        # maigret writes dossiers into ./reports unless redirected.
        self.assertEqual(os.path.isdir("reports"), before)


if __name__ == "__main__":
    unittest.main()
