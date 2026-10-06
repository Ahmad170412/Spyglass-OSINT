"""Tests for metadata.py — file typing and path handling (no external tools)."""

import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

md = imp("metadata")

# Captured from `exiftool -j -G awake.py` on macOS: exiftool has no format
# registered for `.py`, so it sniffs the bytes and reports a Python script as
# plain text. This is the shape the file-typing tests are written against.
_EXIFTOOL_PY = {
    "SourceFile": "/Users/AWNW/awake.py",
    "File:FileName": "awake.py",
    "File:FileSize": "206 bytes",
    "File:FileType": "TXT",
    "File:FileTypeExtension": "txt",
    "File:MIMEType": "text/plain",
    "File:MIMEEncoding": "us-ascii",
    "File:FileModifyDate": "2026:08:13 22:21:39+08:00",
}


class MimeByExtensionTest(unittest.TestCase):
    """The extension table is consulted first precisely so the answer does not
    move between machines: `mimetypes` reads the host OS's mime database."""

    def test_source_extensions_are_named(self):
        self.assertEqual(md._mime_type("/tmp/x.py"), "text/x-python")
        self.assertEqual(md._mime_type("/tmp/x.rb"), "text/x-ruby")
        self.assertEqual(md._mime_type("/tmp/x.rs"), "text/x-rust")
        self.assertEqual(md._mime_type("/tmp/x.go"), "text/x-go")
        self.assertEqual(md._mime_type("/tmp/x.sh"), "application/x-sh")

    def test_common_media_and_document_types_are_named(self):
        self.assertEqual(md._mime_type("/tmp/x.jpg"), "image/jpeg")
        self.assertEqual(md._mime_type("/tmp/x.pdf"), "application/pdf")
        self.assertEqual(md._mime_type("/tmp/x.mp4"), "video/mp4")

    def test_the_extension_is_read_from_either_separator(self):
        # Windows paths reach the module as typed or pasted; splitting on the
        # separator is not how the extension is found, so both spellings of the
        # same file must land on the same type.
        self.assertEqual(md._mime_type("C:\\Users\\ops\\awake.py"), "text/x-python")
        self.assertEqual(md._mime_type("/Users/ops/awake.py"), "text/x-python")

    def test_an_unknown_extension_falls_back_to_the_stdlib(self):
        # `.css` is not in the table above; mimetypes has it on every platform.
        self.assertEqual(md._mime_type("/tmp/x.css"), "text/css")

    def test_nothing_knows_this_file_is_an_octet_stream(self):
        self.assertEqual(md._mime_type("/tmp/x.zzznotarealext"),
                         "application/octet-stream")


class ResolveTypeTest(unittest.TestCase):
    """`sniffed` is exiftool's MIME for the bytes; `ours` is the extension's."""

    def test_a_python_script_is_not_demoted_to_plain_text(self):
        # The bug this exists for: exiftool sniffs .py as text/plain.
        self.assertEqual(md._resolve_type("text/plain", "text/x-python"),
                         "text/x-python")

    def test_a_real_format_exiftool_recognised_beats_an_unknown_extension(self):
        # `.heic` is not in the table, but exiftool knows it.
        self.assertEqual(md._resolve_type("image/heic",
                                          "application/octet-stream"),
                         "image/heic")

    def test_an_extension_we_cannot_name_wins_over_the_generic_sniff(self):
        self.assertEqual(md._resolve_type("text/plain",
                                          "application/octet-stream"),
                         "text/plain")

    def test_agreeing_answers_are_returned_unchanged(self):
        self.assertEqual(md._resolve_type("image/jpeg", "image/jpeg"),
                         "image/jpeg")

    def test_no_exiftool_answer_leaves_ours_alone(self):
        self.assertEqual(md._resolve_type(None, "text/x-python"), "text/x-python")
        self.assertEqual(md._resolve_type("", "text/x-python"), "text/x-python")


class ExtractFileTypeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _touch(self, name, body="#!/usr/bin/env python3\nprint('hi')\n"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def _extract(self, path, meta, sniffed):
        with mock.patch.object(md, "_EXIFTOOL", "/usr/bin/exiftool"), \
             mock.patch.object(md, "_exiftool_extract", return_value=(meta, sniffed)):
            return md.extract(path)

    def test_a_python_script_reports_python_not_txt(self):
        out = self._extract(self._touch("awake.py"), {}, "text/plain")
        self.assertEqual(out["file_type"], "text/x-python")
        self.assertEqual(out["file_name"], "awake.py")

    def test_the_four_duplicate_file_facts_are_reported_once(self):
        # exiftool's FileSize/FileType/FileTypeExtension/MIMEType used to sit
        # beside our file_size/file_type, so one file showed two sizes and two
        # mutually exclusive types. Both spellings are checked, because the bug
        # was two keys for one fact.
        out = self._extract(self._touch("awake.py"),
                            md._clean_exiftool(_EXIFTOOL_PY), "text/plain")
        self.assertEqual([k for k in out
                          if k in ("file_size", "FileSize")], ["file_size"])
        self.assertEqual([k for k in out
                          if k in ("file_type", "FileType",
                                   "FileTypeExtension", "MIMEType")],
                         ["file_type"])
        self.assertEqual(out["file_type"], "text/x-python")

    def test_the_duplicated_keys_are_not_curated_anymore(self):
        for key in ("FileSize", "FileType", "FileTypeExtension", "MIMEType"):
            self.assertNotIn(key, md._CURATED)

    def test_exiftool_still_contributes_its_format_metadata(self):
        out = self._extract(self._touch("shot.jpg"), {"Make": "Canon"},
                            "image/jpeg")
        self.assertEqual(out["Make"], "Canon")
        self.assertEqual(out["file_type"], "image/jpeg")

    def test_without_exiftool_the_extension_is_still_answered(self):
        path = self._touch("awake.py")
        with mock.patch.object(md, "_EXIFTOOL", None):
            out = md.extract(path)
        self.assertEqual(out["file_type"], "text/x-python")

    def test_a_failed_exiftool_run_falls_through_to_the_fallbacks(self):
        path = self._touch("shot.png", "\x89PNG not really")
        with mock.patch.object(md, "_EXIFTOOL", "/usr/bin/exiftool"), \
             mock.patch.object(md, "_exiftool_extract", return_value=(None, None)):
            out = md.extract(path)
        self.assertEqual(out["file_type"], "image/png")

    def test_a_missing_file_reports_the_path_it_looked_for(self):
        missing = os.path.join(self.tmp.name, "nope.py")
        out = md.extract(missing)
        self.assertIn("error", out)
        self.assertIn("nope.py", out["error"])


class ExiftoolCleaningTest(unittest.TestCase):
    def test_the_sniffed_mime_is_pulled_out_of_the_fields(self):
        self.assertEqual(md._exiftool_mime(_EXIFTOOL_PY), "text/plain")

    def test_a_plain_python_script_yields_nothing_to_curate(self):
        # Which is why `_exiftool_extract` distinguishes an empty dict from
        # None: success with nothing to show, not failure.
        self.assertEqual(md._clean_exiftool(_EXIFTOOL_PY), {})

    def test_format_specific_fields_are_kept(self):
        raw = {"File:FileSize": "8.0 kB", "EXIF:ImageWidth": "640",
               "EXIF:Make": "Canon"}
        cleaned = md._clean_exiftool(raw)
        self.assertEqual(cleaned, {"ImageWidth": "640", "Make": "Canon"})


class NormalisePathTest(unittest.TestCase):
    """One normaliser, so the CLI, the menu and the console agree on the path."""

    def test_surrounding_whitespace_is_dropped(self):
        self.assertEqual(md.normalise_path("  /tmp/x.py\n"), "/tmp/x.py")

    def test_paths_quoted_by_the_file_manager_are_unquoted(self):
        quoted = '"' + os.path.join("/tmp", "a file.py") + '"'
        self.assertEqual(md.normalise_path(quoted),
                         os.path.join("/tmp", "a file.py"))
        self.assertEqual(md.normalise_path("'/tmp/x.py'"), "/tmp/x.py")

    def test_a_tilde_is_expanded_for_the_menu_which_has_no_shell(self):
        home = os.path.expanduser("~")
        self.assertEqual(md.normalise_path("~/x.py"), os.path.join(home, "x.py"))

    def test_environment_variables_are_expanded(self):
        # %VAR% on Windows, $VAR elsewhere — both are expandvars' own job, so
        # the test spells the reference in whichever form this platform reads.
        with mock.patch.dict(os.environ,
                             {"SG_CASE_ROOT": os.path.join(os.sep, "cases")}):
            ref = (("%SG_CASE_ROOT%" if md._IS_WINDOWS else "$SG_CASE_ROOT")
                   + os.sep + "x.py")
            self.assertEqual(md.normalise_path(ref),
                             os.path.join(os.sep, "cases", "x.py"))

    def test_separators_are_the_platforms_own(self):
        # Joining rather than concatenating is what keeps this true on Windows.
        self.assertEqual(md.normalise_path("~" + os.sep + "x.py"),
                         os.path.join(os.path.expanduser("~"), "x.py"))

    def test_nothing_in_is_not_an_error_until_the_file_is_looked_for(self):
        self.assertEqual(md.normalise_path(None), "")
        self.assertEqual(md.normalise_path("   "), "")
        self.assertIn("error", md.extract(""))


class CreatedTimeTest(unittest.TestCase):
    class _Stat:
        def __init__(self, birth=None, ctime=1_700_000_000):
            self.st_ctime = ctime
            if birth is not None:
                self.st_birthtime = birth

    def test_birthtime_is_used_where_the_platform_has_it(self):
        out = md._created(self._Stat(birth=1_700_000_000))
        self.assertNotEqual(out, "N/A")
        self.assertIn("2023", out)

    def test_linux_reports_no_creation_time_rather_than_the_wrong_one(self):
        # `st_ctime` is the inode-change time on Linux. Reporting it as a
        # creation time would be a fact this module does not have.
        if md._IS_WINDOWS:
            self.skipTest("Windows reports creation time via st_ctime")
        self.assertEqual(md._created(self._Stat()), "N/A")

    def test_windows_uses_st_ctime_because_there_it_is_creation_time(self):
        with mock.patch.object(md, "_IS_WINDOWS", True):
            out = md._created(self._Stat())
        self.assertNotEqual(out, "N/A")
        self.assertIn("2023", out)


class ModulePlaceholderTest(unittest.TestCase):
    def test_the_file_path_placeholder_is_written_in_this_os_syntax(self):
        # It is rendered verbatim into the console's input, so `/path/to/...`
        # would be an example the OS cannot open.
        modules = imp("modules")
        row = next(m for m in modules.MODULES if m["id"] == "metadata")
        self.assertEqual(row["fields"][0]["ph"],
                         os.path.join(os.path.expanduser("~"), "photo.jpg"))


if __name__ == "__main__":
    unittest.main()
