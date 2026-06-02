#!/usr/bin/env python3
"""Tests for context-anchored IP regex and subnet round-trip (findings 7, 5)."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sanitize_common import CIDR_RE, IPV4_RE  # noqa: E402
from sanitize_filter import (  # noqa: E402
    SubnetRule,
    apply_subnet_rules,
)


class TestIpv4Regex(unittest.TestCase):
    def test_matches_plain_ip(self) -> None:
        self.assertEqual(IPV4_RE.findall("host: 192.168.1.10"), ["192.168.1.10"])

    def test_skips_version_like_tokens(self) -> None:
        text = "helm-3.14.2 image: v1.21.0 release-2.0.1"
        self.assertEqual(IPV4_RE.findall(text), [])

    def test_skips_ip_preceded_by_digit(self) -> None:
        self.assertEqual(IPV4_RE.findall("1192.168.1.10"), [])

    def test_cidr_before_ip_in_string(self) -> None:
        found = CIDR_RE.findall("range: 192.168.50.0/24")
        self.assertEqual(found, ["192.168.50.0/24"])


class TestSubnetRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = [
            SubnetRule("192.168.50.0/24", "10.0.0.0/24"),
        ]

    def test_ip_round_trip(self) -> None:
        original = "server: 192.168.50.11\n"
        cleaned = apply_subnet_rules(original, self.rules, reverse=False)
        self.assertIn("10.0.0.11", cleaned)
        self.assertNotIn("192.168.50.11", cleaned)
        restored = apply_subnet_rules(cleaned, self.rules, reverse=True)
        self.assertEqual(restored, original)

    def test_cidr_round_trip(self) -> None:
        original = 'cidr: "192.168.50.0/24"\n'
        cleaned = apply_subnet_rules(original, self.rules, reverse=False)
        self.assertIn("10.0.0.0/24", cleaned)
        restored = apply_subnet_rules(cleaned, self.rules, reverse=True)
        self.assertEqual(restored, original)


class TestDummyOverlapValidation(unittest.TestCase):
    def test_overlapping_dummy_cidrs_raise(self) -> None:
        from sanitize_filter import _validate_dummy_subnet_overlap

        rules = [
            SubnetRule("192.168.1.0/24", "10.0.1.0/24"),
            SubnetRule("192.168.2.0/24", "10.0.1.0/24"),
        ]
        with self.assertRaises(ValueError) as ctx:
            _validate_dummy_subnet_overlap(rules)
        self.assertIn("overlap", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
