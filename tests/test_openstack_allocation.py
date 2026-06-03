#!/usr/bin/env python3
"""OpenStack example: identity fields stay clear; passwords sanitize (fix 1)."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILTER = ROOT / "scripts" / "sanitize_filter.py"
FIXTURE = ROOT / "tests" / "fixtures" / "openstack-allocation.yaml"
CONFIG = ROOT / "tests" / "fixtures" / "sanitization.json"
LEARNED = ROOT / "tests" / "fixtures" / ".openstack-learned-test.json"


class TestOpenstackAllocationClean(unittest.TestCase):
    def setUp(self) -> None:
        if LEARNED.is_file():
            LEARNED.unlink()

    def test_clean_identity_fields_unchanged_passwords_dummy(self) -> None:
        env = {
            **os.environ,
            "SANITIZATION_CONFIG": str(CONFIG),
            "SANITIZATION_LEARNED": str(LEARNED),
        }
        raw = FIXTURE.read_text(encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(FILTER), "clean"],
            input=raw,
            capture_output=True,
            text=True,
            env=env,
            check=True,
            cwd=ROOT,
        )
        out = proc.stdout
        self.assertIn("admin_user: keystone-admin", out)
        self.assertIn("auth_url: https://identity.example/v3", out)
        self.assertIn("IdentityAuthURL: https://identity.example/v3", out)
        self.assertRegex(out, r"AdminPassword: DUMMY_SEC_")
        self.assertRegex(out, r"ldap_bind_password: DUMMY_SEC_")
        self.assertNotIn("cmVkaGF0", out)


if __name__ == "__main__":
    unittest.main()
