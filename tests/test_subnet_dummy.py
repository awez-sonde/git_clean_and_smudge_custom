#!/usr/bin/env python3
"""Dummy subnet assignment and validation (fix 2)."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sanitize_common import (  # noqa: E402
    discover_subnet_rules,
    suggest_dummy_cidr,
)
from sanitize_filter import (  # noqa: E402
    SubnetRule,
    apply_subnet_rules,
    _validate_dummy_subnet_overlap,
)


class TestSuggestDummyCidr(unittest.TestCase):
    def test_slash31_dummy_same_prefixlen_and_roundtrip(self) -> None:
        actual = ipaddress.ip_network("10.10.10.200/31")
        all_actuals = {actual}
        dummy = suggest_dummy_cidr(actual, set(), all_actuals)
        self.assertEqual(dummy.prefixlen, 31)
        self.assertFalse(dummy.overlaps(actual))
        rules = [SubnetRule(str(actual), str(dummy))]
        _validate_dummy_subnet_overlap(rules)
        original = "peer: 10.10.10.201\nrange: 10.10.10.200/31\n"
        cleaned = apply_subnet_rules(original, rules, reverse=False)
        self.assertIn(str(dummy.network_address + 1), cleaned)
        self.assertNotIn("10.10.10.201", cleaned)
        restored = apply_subnet_rules(cleaned, rules, reverse=True)
        self.assertEqual(restored, original)

    def test_avoids_real_10_space_when_mapping_other_actual(self) -> None:
        customer = ipaddress.ip_network("10.10.10.200/31")
        other = ipaddress.ip_network("192.168.55.0/24")
        all_actuals = {customer, other}
        used: set[ipaddress.IPv4Network] = set()
        d_customer = suggest_dummy_cidr(customer, used, all_actuals)
        used.add(d_customer)
        d_other = suggest_dummy_cidr(other, used, all_actuals)
        self.assertFalse(d_customer.overlaps(customer))
        self.assertFalse(d_other.overlaps(customer))
        self.assertFalse(d_other.overlaps(other))
        self.assertNotEqual(int(d_other.network_address) >> 16, int(customer.network_address) >> 16)
        rules = [
            SubnetRule(str(customer), str(d_customer)),
            SubnetRule(str(other), str(d_other)),
        ]
        _validate_dummy_subnet_overlap(rules)
        original = (
            "underlay: 10.10.10.201\n"
            "customer_cidr: 10.10.10.200/31\n"
            "app: 192.168.55.42\n"
        )
        cleaned = apply_subnet_rules(original, rules, reverse=False)
        restored = apply_subnet_rules(cleaned, rules, reverse=True)
        self.assertEqual(restored, original)

    def test_mixed_prefixes_discover_distinct_dummies(self) -> None:
        nets = {
            ipaddress.ip_network("192.168.77.0/24"),
            ipaddress.ip_network("10.20.30.0/28"),
            ipaddress.ip_network("10.10.10.200/31"),
        }
        rules_data = discover_subnet_rules(nets)
        rules = [
            SubnetRule(r["actual_cidr"], r["dummy_cidr"]) for r in rules_data
        ]
        _validate_dummy_subnet_overlap(rules)
        dummies = [r.dummy_net for r in rules]
        for i, a in enumerate(dummies):
            for b in dummies[i + 1 :]:
                self.assertFalse(a.overlaps(b))
            for actual in nets:
                self.assertFalse(a.overlaps(actual))
        fixture = (
            Path(__file__).resolve().parent / "fixtures" / "subnet-mixed-prefixes.yaml"
        )
        original = fixture.read_text(encoding="utf-8")
        cleaned = apply_subnet_rules(original, rules, reverse=False)
        restored = apply_subnet_rules(cleaned, rules, reverse=True)
        self.assertEqual(restored, original)


class TestDummyOverlapValidation(unittest.TestCase):
    def test_dummy_overlaps_foreign_actual_raises(self) -> None:
        rules = [
            SubnetRule("192.168.1.0/24", "10.10.10.0/24"),
            SubnetRule("10.10.10.0/24", "192.0.2.0/24"),
        ]
        with self.assertRaises(ValueError) as ctx:
            _validate_dummy_subnet_overlap(rules)
        self.assertIn("overlaps actual", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
