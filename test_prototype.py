"""
================================================================================
  CyberShield IR - Comprehensive Automated Test Suite
  Tests: Persistence | Hash-Linked Audit Chain | Dual Hashing | Detection Engine
================================================================================
"""

import unittest
import os
import sqlite3
import hashlib
import json
import base64
import time

from database import (
    init_db,
    save_incident,
    get_incidents,
    save_evidence_record,
    get_evidence_list,
    add_audit_entry,
    verify_audit_chain,
    get_db_connection,
    calculate_sha256_bytes,
    DB_FILE
)
from detection_engine import (
    calculate_risk_score,
    analyze_security_logs,
    evaluate_detection_benchmark
)

class TestCyberShieldDFIR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    # ─────────────────────────────────────────────────────────────────────────
    # 1. TEST: SQLite Persistence
    # ─────────────────────────────────────────────────────────────────────────
    def test_sqlite_persistence(self):
        """Verify that incidents written to SQLite persist and can be reloaded."""
        unique_id = f"CORP-TEST-{time.time_ns()}"
        test_case = {
            "id": unique_id,
            "title": "Automated Unit Test Incident",
            "asset": "critical",
            "vector": "ransomware",
            "cost": 1500000,
            "systems": 5,
            "severity": "SEV-1 CRITICAL",
            "sla": "< 15 minutes",
            "score": 95,
            "status": "Test Status",
            "analyst": "Automated Tester",
            "detection_rule": "TEST-RULE"
        }
        saved_id = save_incident(test_case)
        self.assertEqual(saved_id, unique_id)

        # Query directly via separate raw connection to verify persistence on disk
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title, score, severity FROM incidents WHERE id = ?", (unique_id,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["title"], "Automated Unit Test Incident")
            self.assertEqual(row["score"], 95)
            self.assertEqual(row["severity"], "SEV-1 CRITICAL")

    # ─────────────────────────────────────────────────────────────────────────
    # 2. TEST: Cryptographic Hash-Linked Audit Chain & Tamper Detection
    # ─────────────────────────────────────────────────────────────────────────
    def test_hash_linked_audit_chain(self):
        """Verify hash-chaining and prove that unauthorized record edits are detected."""
        # 1. Add valid entry
        entry = add_audit_entry("TestAnalyst", "TEST_ACTION", f"Testing valid chain link {time.time_ns()}")
        self.assertIn("entry_hash", entry)

        # 2. Verify chain is currently 100% valid
        verification = verify_audit_chain()
        self.assertTrue(verification["valid"], f"Audit chain should be valid: {verification.get('reason')}")

        # 3. Simulate unauthorized database tampering on an existing row
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE audit_chain SET details = 'TAMPERED DETAILS' WHERE seq = ?", (entry["seq"],))
            conn.commit()

        # 4. Verification MUST now detect tampering
        tamper_check = verify_audit_chain()
        self.assertFalse(tamper_check["valid"], "Tamper check should fail when a row is edited without valid hash recomputation.")
        self.assertEqual(tamper_check["broken_seq"], entry["seq"])
        self.assertIn("Content tampering detected", tamper_check["reason"])

        # 5. Restore original record to maintain test environment sanity
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE audit_chain SET details = ? WHERE seq = ?", (entry["details"], entry["seq"]))
            conn.commit()

        restored_check = verify_audit_chain()
        self.assertTrue(restored_check["valid"], "Chain should be valid once restored.")

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TEST: Real Dual SHA-256 Hashing, Integrity Verification & Duplicates
    # ─────────────────────────────────────────────────────────────────────────
    def test_dual_sha256_verification_and_duplicates(self):
        """Verify real file byte hashing, client vs backend matching, corruption flagging, and duplicate rejection."""
        unique_bytes = f"CRITICAL_FORENSIC_MEMORY_DUMP_{time.time_ns()}".encode("utf-8")
        expected_hash = hashlib.sha256(unique_bytes).hexdigest().lower()

        # A. Successful Match
        res = save_evidence_record(
            filename=f"memory_sample_{time.time_ns()}.bin",
            file_bytes=unique_bytes,
            client_sha256=expected_hash,
            stage="Volatile Memory (RAM)",
            analyst="Lead DFIR Analyst",
            host="CORP-DC01",
            acquisition_method="WinPmem Raw Stream"
        )
        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("integrity_status"), "VERIFIED_MATCH")
        self.assertEqual(res.get("backend_sha256"), expected_hash)

        # B. Duplicate Detection
        dup_res = save_evidence_record(
            filename=f"duplicate_{time.time_ns()}.bin",
            file_bytes=unique_bytes,
            client_sha256=expected_hash,
            stage="Volatile Memory (RAM)",
            analyst="Lead DFIR Analyst",
            host="CORP-DC01",
            acquisition_method="WinPmem Raw Stream"
        )
        self.assertEqual(dup_res.get("status"), "duplicate")
        self.assertIn("Duplicate evidence detected", dup_res.get("message"))

        # C. Hash Mismatch / Corruption in Transit
        corrupt_content = f"CORRUPTED_BYTES_{time.time_ns()}".encode("utf-8")
        mismatch_res = save_evidence_record(
            filename=f"corrupted_{time.time_ns()}.bin",
            file_bytes=corrupt_content,
            client_sha256="0" * 64,  # bogus claimed hash
            stage="Volatile Memory (RAM)",
            analyst="Lead DFIR Analyst",
            host="CORP-DC01",
            acquisition_method="WinPmem Raw Stream"
        )
        self.assertEqual(mismatch_res.get("status"), "error")
        self.assertIn("Hash verification failed", mismatch_res.get("message"))

    # ─────────────────────────────────────────────────────────────────────────
    # 4. TEST: Threat Detection Engine & Explanations
    # ─────────────────────────────────────────────────────────────────────────
    def test_detection_engine_rules_and_explanations(self):
        """Verify that rules trigger appropriately with diagnostic explanations."""
        events = [
            {"username": "cfo_user", "source_ip": "198.51.100.5", "event_type": "LOGIN_FAILED", "event_id": 4625, "details": "Bad pass 1"},
            {"username": "cfo_user", "source_ip": "198.51.100.5", "event_type": "LOGIN_FAILED", "event_id": 4625, "details": "Bad pass 2"},
            {"username": "cfo_user", "source_ip": "198.51.100.5", "event_type": "LOGIN_FAILED", "event_id": 4625, "details": "Bad pass 3"},
            {"username": "cfo_user", "source_ip": "198.51.100.5", "event_type": "LOGIN_FAILED", "event_id": 4625, "details": "Bad pass 4"},
            {"username": "cfo_user", "source_ip": "203.0.113.10", "event_type": "LOGIN_SUCCESS", "event_id": 4624, "details": "Foreign ASN token exchange"},
            {"username": "SYSTEM", "source_ip": "10.0.10.15", "event_type": "SHADOW_PURGE", "event_id": 7045, "details": "vssadmin.exe delete shadows /all /quiet"}
        ]

        alerts = analyze_security_logs(events)
        rule_ids = [a["rule_id"] for a in alerts]

        self.assertIn("BRUTE-FORCE-01", rule_ids)
        self.assertIn("IMPOSSIBLE-TRAVEL-02", rule_ids)
        self.assertIn("SHADOW-PURGE-04", rule_ids)

        # Check that each alert includes a clear explanation
        for alert in alerts:
            self.assertTrue(len(alert["explanation"]) > 20, "Alert should contain detailed explanation.")
            self.assertIn(alert["rule_id"], alert["explanation"])

    # ─────────────────────────────────────────────────────────────────────────
    # 5. TEST: Quantitative Risk Scoring Formula
    # ─────────────────────────────────────────────────────────────────────────
    def test_risk_scoring_formula(self):
        """Verify mathematical bounds, weights, and SLA classification."""
        # Critical Tier 0 + Ransomware + High exposure + High blast radius -> 100/100 SEV-1
        crit = calculate_risk_score("critical", "ransomware", 2000000, 10)
        self.assertEqual(crit["score"], 100)
        self.assertEqual(crit["level"], "SEV-1 CRITICAL")
        self.assertEqual(crit["sla"], "< 15 minutes")

        # Low Tier 3 + Recon + Low cost + 1 system -> SEV-4 LOW
        low = calculate_risk_score("low", "recon", 5000, 1)
        self.assertEqual(low["score"], 5 + 10 + 2 + 2) # 19
        self.assertEqual(low["level"], "SEV-4 LOW")
        self.assertEqual(low["sla"], "< 8 hours")

        # Benchmark evaluation metrics (Precision, Recall)
        benchmark = evaluate_detection_benchmark()
        self.assertGreaterEqual(benchmark["precision"], 0.90)
        self.assertGreaterEqual(benchmark["recall"], 0.90)

if __name__ == "__main__":
    unittest.main()
