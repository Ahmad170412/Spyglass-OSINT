"""Tests for ip.py: domain detection and resolution helpers (no network)."""

import unittest

from helpers import imp

ip = imp("ip")


class IsDomainTest(unittest.TestCase):
    def test_ipv4_is_not_domain(self):
        self.assertFalse(ip._is_domain("8.8.8.8"))

    def test_hostname_is_domain(self):
        self.assertTrue(ip._is_domain("example.com"))
        self.assertTrue(ip._is_domain("sub.example.co.uk"))

    def test_ipv6_is_not_domain(self):
        self.assertFalse(ip._is_domain("2001:db8::1"))


class ResolveTest(unittest.TestCase):
    def test_ipv4_passthrough(self):
        self.assertEqual(ip._resolve("127.0.0.1"), "127.0.0.1")

    def test_invalid_ipv4_rejected(self):
        self.assertIsNone(ip._resolve("999.1.1.1"))

    def test_localhost_resolves_offline(self):
        self.assertIsNotNone(ip._resolve("localhost"))


if __name__ == "__main__":
    unittest.main()
