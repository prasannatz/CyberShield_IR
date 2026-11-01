"""
================================================================================
  CyberShield IR - Automated System Test Suite & CO Verification
  Corporate IT Edition
  Runs automated unit & integration checks on the Python backend, triage engine,
  playbooks, hash algorithms, and audit logging.
================================================================================
"""

import unittest
import json
import os
import hashlib
from app import score_threat, calculate_sha256, PLAYBOOKS

class TestCyberShieldIncidentResponse(unittest.TestCase):

    def test_co2_threat_triage_critical(self):
        """Verify that Tier-0 Domain Controller with Ransomware triggers SEV-1."""
        res = score_threat(asset="critical", vector="ransomware", cost=1200000, systems=4)
        self.assertEqual(res["level"], "SEV-1 CRITICAL")
        self.assertEqual(res["sla"], "< 15 minutes")
        self.assertGreaterEqual(res["score"], 80)

    def test_co2_threat_triage_medium(self):
        """Verify that lower impact asset and vector triggers appropriate severity."""
        res = score_threat(asset="low", vector="ddos", cost=20000, systems=1)
        self.assertIn(res["level"], ["SEV-3 MEDIUM", "SEV-4 LOW"])

    def test_co4_containment_playbook_integrity(self):
        """Verify that all major Corporate IT threat vectors have defined containment steps."""
        self.assertIn("ransomware", PLAYBOOKS)
        self.assertIn("bec", PLAYBOOKS)
        self.assertIn("vpn", PLAYBOOKS)
        self.assertIn("ddos", PLAYBOOKS)
        self.assertGreaterEqual(len(PLAYBOOKS["ransomware"]), 4)
        self.assertGreaterEqual(len(PLAYBOOKS["bec"]), 3)
        self.assertGreaterEqual(len(PLAYBOOKS["vpn"]), 3)

    def test_co5_cryptographic_hash_generation(self):
        """Verify SHA-256 evidence integrity hashing is mathematically sound."""
        test_string = "CORP_DC01_RAM_VOLATILE_EVIDENCE_2026"
        expected = hashlib.sha256(test_string.encode("utf-8")).hexdigest()
        actual = calculate_sha256(test_string)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 64)

if __name__ == "__main__":
    print("\n[+] Running CyberShield IR Automated Verification Suite (Corporate IT Edition)...")
    unittest.main(verbosity=2)
