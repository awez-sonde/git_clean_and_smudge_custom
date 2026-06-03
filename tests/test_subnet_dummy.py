#!/usr/bin/env python3
"""Dummy subnet assignment and validation — all prefix lengths /8–/32."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sanitize_common import (  # noqa: E402
    RESERVED_DUMMY_NETS,
    RFC6598_DUMMY_POOL,
    discover_subnet_rules,
    suggest_dummy_cidr,
)
from sanitize_filter import (  # noqa: E402
    SubnetRule,
    apply_subnet_rules,
    _validate_dummy_subnet_overlap,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _assert_not_in_rfc5737(dummy: ipaddress.IPv4Network) -> None:
    for doc in RESERVED_DUMMY_NETS:
        if dummy.overlaps(doc):
            raise AssertionError(f"{dummy} overlaps RFC 5737 pool {doc}")


class TestSuggestDummyCidr(unittest.TestCase):
    def _roundtrip(self, original: str, rules: list[SubnetRule]) -> None:
        cleaned = apply_subnet_rules(original, rules, reverse=False)
        restored = apply_subnet_rules(cleaned, rules, reverse=True)
        self.assertEqual(restored, original)

    def test_slash32_host_route_roundtrip(self) -> None:
        actual = ipaddress.ip_network("10.10.10.5/32")
        all_actuals = {actual}
        dummy = suggest_dummy_cidr(actual, set(), all_actuals)
        self.assertEqual(dummy.prefixlen, 32)
        self.assertFalse(dummy.overlaps(actual))
        rules = [SubnetRule(str(actual), str(dummy))]
        _validate_dummy_subnet_overlap(rules)
        self._roundtrip(
            "host: 10.10.10.5\nroute: 10.10.10.5/32\n",
            rules,
        )

    def test_slash23_supernet_in_cgnat_not_rfc5737(self) -> None:
        actual = ipaddress.ip_network("192.168.0.0/23")
        all_actuals = {actual}
        dummy = suggest_dummy_cidr(actual, set(), all_actuals)
        self.assertEqual(dummy.prefixlen, 23)
        _assert_not_in_rfc5737(dummy)
        self.assertTrue(dummy.subnet_of(RFC6598_DUMMY_POOL))
        rules = [SubnetRule(str(actual), str(dummy))]
        _validate_dummy_subnet_overlap(rules)
        self._roundtrip(
            "gateway: 192.168.0.1\naggregate: 192.168.0.0/23\n",
            rules,
        )

    def test_slash16_roundtrip(self) -> None:
        actual = ipaddress.ip_network("172.16.0.0/16")
        all_actuals = {actual}
        dummy = suggest_dummy_cidr(actual, set(), all_actuals)
        self.assertEqual(dummy.prefixlen, 16)
        self.assertFalse(dummy.overlaps(actual))
        rules = [SubnetRule(str(actual), str(dummy))]
        _validate_dummy_subnet_overlap(rules)
        self._roundtrip(
            "router: 172.16.1.1\nregion: 172.16.0.0/16\n",
            rules,
        )

    def test_slash31_dummy_same_prefixlen_and_roundtrip(self) -> None:
        actual = ipaddress.ip_network("10.10.10.200/31")
        all_actuals = {actual}
        dummy = suggest_dummy_cidr(actual, set(), all_actuals)
        self.assertEqual(dummy.prefixlen, 31)
        self.assertFalse(dummy.overlaps(actual))
        rules = [SubnetRule(str(actual), str(dummy))]
        _validate_dummy_subnet_overlap(rules)
        self._roundtrip(
            "peer: 10.10.10.201\nrange: 10.10.10.200/31\n",
            rules,
        )

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
        rules = [
            SubnetRule(str(customer), str(d_customer)),
            SubnetRule(str(other), str(d_other)),
        ]
        _validate_dummy_subnet_overlap(rules)
        self._roundtrip(
            "underlay: 10.10.10.201\n"
            "customer_cidr: 10.10.10.200/31\n"
            "app: 192.168.55.42\n",
            rules,
        )

    def test_mixed_23_24_28_31_32_distinct_byte_identical_roundtrip(self) -> None:
        nets = {
            ipaddress.ip_network("192.168.0.0/23"),
            ipaddress.ip_network("192.168.77.0/24"),
            ipaddress.ip_network("10.20.30.0/28"),
            ipaddress.ip_network("10.10.10.200/31"),
            ipaddress.ip_network("10.10.10.5/32"),
        }
        rules_data = discover_subnet_rules(nets)
        rules = [SubnetRule(r["actual_cidr"], r["dummy_cidr"]) for r in rules_data]
        for r in rules:
            self.assertEqual(r.dummy_net.prefixlen, r.actual_net.prefixlen)
        dummies = [r.dummy_net for r in rules]
        for i, a in enumerate(dummies):
            for b in dummies[i + 1 :]:
                self.assertFalse(a.overlaps(b))
            for actual in nets:
                self.assertFalse(a.overlaps(actual))
        _validate_dummy_subnet_overlap(rules)
        for r in rules:
            if r.actual_net.prefixlen == 23:
                _assert_not_in_rfc5737(r.dummy_net)
        original = (FIXTURES / "subnet-all-prefixes.yaml").read_text(encoding="utf-8")
        self._roundtrip(original, rules)

    def test_mixed_prefixes_discover_distinct_dummies(self) -> None:
        nets = {
            ipaddress.ip_network("192.168.77.0/24"),
            ipaddress.ip_network("10.20.30.0/28"),
            ipaddress.ip_network("10.10.10.200/31"),
        }
        rules_data = discover_subnet_rules(nets)
        rules = [SubnetRule(r["actual_cidr"], r["dummy_cidr"]) for r in rules_data]
        _validate_dummy_subnet_overlap(rules)
        original = (FIXTURES / "subnet-mixed-prefixes.yaml").read_text(encoding="utf-8")
        self._roundtrip(original, rules)


class TestSuggestDummyCidrErrors(unittest.TestCase):
    def test_exhausted_pools_raises_clear_error(self) -> None:
        actual = ipaddress.ip_network("10.0.0.0/23")
        tiny_pools = (ipaddress.ip_network("192.0.2.0/24"),)
        with self.assertRaises(ValueError) as ctx:
            suggest_dummy_cidr(
                actual,
                set(),
                {actual},
                address_pools=tiny_pools,
            )
        msg = str(ctx.exception)
        self.assertIn("/23", msg)
        self.assertIn("192.0.2.0/24", msg)
        self.assertIn("non-overlapping dummy", msg.lower())


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
