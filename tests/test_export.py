"""Tests for export.py: flattening and JSON/CSV file writing."""

import csv
import json
import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

export = imp("export")


class FlattenTest(unittest.TestCase):
    def test_nested_dict_and_list(self):
        rows = export._flatten({"a": {"b": 1, "c": [10, 20]}, "d": "x"})
        joined = {k: v for row in rows for k, v in row.items()}
        self.assertEqual(joined["a_b"], 1)
        self.assertEqual(joined["d"], "x")

    def test_plain_scalar(self):
        self.assertEqual(export._flatten("hi"), [{"value": "hi"}])

    def test_empty_dict(self):
        self.assertEqual(export._flatten({}), [{"value": "{}"}])


class WriteTest(unittest.TestCase):
    def test_json_output_writes_sanitized_file(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(export._ui, "info"):
            old = os.getcwd()
            os.chdir(tmp)
            try:
                path = export.json_output({"a": 1}, "u@x.com/y", "email")
                self.assertTrue(path.endswith(".json"))
                self.assertIn("spyglass_email_u_x.com_y_", path)
                with open(path) as f:
                    self.assertEqual(json.load(f), {"a": 1})
            finally:
                os.chdir(old)

    def test_csv_output_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(export._ui, "info"):
            old = os.getcwd()
            os.chdir(tmp)
            try:
                path = export.csv_output({"a": {"b": 1}}, "example.com/x", "website")
                self.assertTrue(path.endswith(".csv"))
                self.assertIn("spyglass_website_example.com_x_", path)
                with open(path) as f:
                    content = f.read()
                self.assertIn("a_b", content)
                self.assertIn("1", content)
            finally:
                os.chdir(old)

    def test_csv_output_heterogeneous_rows(self):
        # A result mixing top-level scalars with nested dicts/list items used to
        # crash DictWriter because rows carried different key sets.
        result = {
            "query": "example.com",
            "type": "domain",
            "dns_email_security": {"spf": "v=spf1 -all", "dmarc": "p=reject"},
            "subdomains": ["www.example.com", "mail.example.com"],
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(export._ui, "info"):
            old = os.getcwd()
            os.chdir(tmp)
            try:
                path = export.csv_output(result, "example.com", "website")
                with open(path, newline="") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    self.assertEqual(len(rows), 4)
                    # Unioned schema: every column is present in the header.
                    for col in ("query", "dns_email_security_dmarc", "subdomains"):
                        self.assertIn(col, reader.fieldnames)
                    values = {k: v for row in rows for k, v in row.items() if v}
                    self.assertEqual(values["query"], "example.com")
                    self.assertEqual(values["dns_email_security_dmarc"], "p=reject")
                    self.assertEqual(values["subdomains"], "mail.example.com")
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
