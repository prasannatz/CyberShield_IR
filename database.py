"""
================================================================================
  CyberShield IR - SQLite Persistence & Cryptographic Audit Storage Layer
  Standards: RFC 3227 (Volatility) | ISO/IEC 27037 (Digital Evidence Integrity)
================================================================================
"""

import sqlite3
import hashlib
import datetime
import os
import json
from typing import Dict, List, Optional, Tuple, Any

DB_FILE = "cybershield.db"
EVIDENCE_VAULT_DIR = "evidence_vault"

def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def calculate_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()

def calculate_sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().lower()

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(EVIDENCE_VAULT_DIR, exist_ok=True)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                asset TEXT NOT NULL,
                vector TEXT NOT NULL,
                cost INTEGER NOT NULL,
                systems INTEGER NOT NULL,
                severity TEXT NOT NULL,
                sla TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                analyst TEXT NOT NULL,
                detection_rule TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                filename TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                filetype TEXT NOT NULL,
                stage TEXT NOT NULL,
                analyst TEXT NOT NULL,
                acquisition_method TEXT NOT NULL,
                host TEXT NOT NULL,
                client_sha256 TEXT NOT NULL,
                backend_sha256 TEXT NOT NULL,
                integrity_status TEXT NOT NULL,
                storage_path TEXT,
                acquisition_time TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_id INTEGER,
                details TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS soar_actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                playbook TEXT NOT NULL,
                action_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                command_input TEXT NOT NULL,
                execution_output TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                approval_status TEXT NOT NULL,
                approved_by TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM audit_chain")
        if cursor.fetchone()[0] == 0:
            genesis_time = utc_now()
            genesis_prev = "0" * 64
            genesis_actor = "SYSTEM_INITIALIZER"
            genesis_action = "GENESIS_BLOCK"
            genesis_details = "CyberShield IR Cryptographic Audit Chain Initialized."
            genesis_payload = f"{genesis_prev}|{genesis_time}|{genesis_actor}|{genesis_action}|{genesis_details}"
            genesis_hash = calculate_sha256_str(genesis_payload)
            cursor.execute("""
                INSERT INTO audit_chain (prev_hash, timestamp, actor, action, details, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (genesis_prev, genesis_time, genesis_actor, genesis_action, genesis_details, genesis_hash))
            conn.commit()

        cursor.execute("SELECT COUNT(*) FROM incidents")
        if cursor.fetchone()[0] == 0:
            sample_incidents = [
                ("CORP-901", "LockBit 3.0 Ransomware on DC01 & File Server", "critical", "ransomware", 1200000, 4, "SEV-1 CRITICAL", "< 15 min", 95, "Containment Active", "Lead IR Analyst", "SHADOW-PURGE-04", utc_now()),
                ("CORP-902", "AiTM Token Hijack - CFO Executive Mailbox", "high", "bec", 650000, 1, "SEV-2 HIGH", "< 30 min", 78, "Under Investigation", "Threat Intel Specialist", "IMPOSSIBLE-TRAVEL-02", utc_now()),
                ("CORP-903", "50 Gbps SYN Flood on Customer SSO Portal", "medium", "ddos", 20000, 2, "SEV-3 MEDIUM", "< 2 hours", 45, "Mitigated by WAF", "SecOps Engineer", "BRUTE-FORCE-01", utc_now())
            ]
            cursor.executemany("""
                INSERT INTO incidents (id, title, asset, vector, cost, systems, severity, sla, score, status, analyst, detection_rule, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_incidents)
            conn.commit()

        cursor.execute("SELECT COUNT(*) FROM security_events")
        if cursor.fetchone()[0] == 0:
            sample_events = [
                (utc_now(), "198.51.100.42", "admin_cfo", "LOGIN_FAILED", 4625, "Failed password attempt via Outlook Web App (attempt 1)", "SUSPICIOUS"),
                (utc_now(), "198.51.100.42", "admin_cfo", "LOGIN_FAILED", 4625, "Failed password attempt via Outlook Web App (attempt 2)", "SUSPICIOUS"),
                (utc_now(), "198.51.100.42", "admin_cfo", "LOGIN_FAILED", 4625, "Failed password attempt via Outlook Web App (attempt 3)", "SUSPICIOUS"),
                (utc_now(), "198.51.100.42", "admin_cfo", "LOGIN_FAILED", 4625, "Failed password attempt via Outlook Web App (attempt 4)", "ALERT_TRIGGERED"),
                (utc_now(), "203.0.113.19", "admin_cfo", "LOGIN_SUCCESS", 4624, "Successful MFA bypass token exchange from foreign ASN", "COMPROMISED"),
                (utc_now(), "10.0.10.15", "SYSTEM", "SHADOW_PURGE", 7045, "vssadmin.exe delete shadows /all /quiet detected on CORP-DC01", "CRITICAL_THREAT")
            ]
            cursor.executemany("""
                INSERT INTO security_events (timestamp, source_ip, username, event_type, event_id, details, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, sample_events)
            conn.commit()

def add_audit_entry(actor: str, action: str, details: str) -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1")
        row = cursor.fetchone()
        prev_hash = row[0] if row else ("0" * 64)
        timestamp = utc_now()
        payload = f"{prev_hash}|{timestamp}|{actor}|{action}|{details}"
        entry_hash = calculate_sha256_str(payload)
        cursor.execute("""
            INSERT INTO audit_chain (prev_hash, timestamp, actor, action, details, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (prev_hash, timestamp, actor, action, details, entry_hash))
        seq = cursor.lastrowid
        conn.commit()
        return {"seq": seq, "prev_hash": prev_hash, "timestamp": timestamp, "actor": actor, "action": action, "details": details, "entry_hash": entry_hash}

def verify_audit_chain() -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT seq, prev_hash, timestamp, actor, action, details, entry_hash FROM audit_chain ORDER BY seq ASC")
        rows = cursor.fetchall()
        if not rows:
            return {"valid": False, "total_records": 0, "message": "Audit chain is empty."}
        expected_prev = "0" * 64
        for row in rows:
            seq, prev_hash, ts, actor, action, details, entry_hash = row["seq"], row["prev_hash"], row["timestamp"], row["actor"], row["action"], row["details"], row["entry_hash"]
            if seq == 1:
                if prev_hash != ("0" * 64):
                    return {"valid": False, "broken_seq": 1, "reason": "Invalid Genesis prev_hash"}
            else:
                if prev_hash != expected_prev:
                    return {"valid": False, "broken_seq": seq, "reason": f"Chain link broken at record #{seq}: prev_hash does not match previous entry_hash."}
            payload = f"{prev_hash}|{ts}|{actor}|{action}|{details}"
            recomputed = calculate_sha256_str(payload)
            if recomputed != entry_hash:
                return {"valid": False, "broken_seq": seq, "reason": f"Content tampering detected at record #{seq}: recomputed hash does not match stored hash."}
            expected_prev = entry_hash
        return {"valid": True, "total_records": len(rows), "head_hash": expected_prev, "message": f"Cryptographic integrity verified across all {len(rows)} chained audit records. Zero tampering detected."}

def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT seq, prev_hash, timestamp, actor, action, details, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

def save_incident(incident: Dict[str, Any]) -> str:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (id, title, asset, vector, cost, systems, severity, sla, score, status, analyst, detection_rule, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident["id"], incident["title"], incident["asset"], incident["vector"],
            incident["cost"], incident["systems"], incident["severity"], incident["sla"],
            incident["score"], incident.get("status", "Assessed"), incident.get("analyst", "Analyst Desk"),
            incident.get("detection_rule", "MANUAL-TRIAGE"), incident.get("created_at", utc_now())
        ))
        conn.commit()
    add_audit_entry(
        actor=incident.get("analyst", "Analyst Desk"),
        action="INCIDENT_CREATED",
        details=f"[{incident['id']}] {incident['title']} triaged as {incident['severity']} (Score: {incident['score']}/100)"
    )
    return incident["id"]

def get_incidents() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]

def save_evidence_record(filename: str, file_bytes: bytes, client_sha256: str, stage: str, analyst: str, host: str, acquisition_method: str, incident_id: Optional[str] = None) -> Dict[str, Any]:
    backend_sha256 = calculate_sha256_bytes(file_bytes)
    filesize = len(file_bytes)
    now = utc_now()
    client_sha256 = client_sha256.strip().lower()
    _, ext = os.path.splitext(filename)
    filetype = ext.lower() if ext else "raw/binary"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, filename, acquisition_time FROM evidence WHERE backend_sha256 = ?", (backend_sha256,))
        dup = cursor.fetchone()
        if dup:
            add_audit_entry(
                actor=analyst,
                action="EVIDENCE_DUPLICATE_REJECTED",
                details=f"File {filename} ({filesize} B) duplicate SHA-256 matching {dup['id']} ({dup['filename']})"
            )
            return {
                "status": "duplicate",
                "message": f"Duplicate evidence detected: Matches existing record {dup['id']} ({dup['filename']}) acquired at {dup['acquisition_time']}.",
                "existing_id": dup["id"],
                "sha256": backend_sha256
            }
        if client_sha256 and client_sha256 != backend_sha256:
            add_audit_entry(
                actor=analyst,
                action="EVIDENCE_INTEGRITY_FAILED",
                details=f"INTEGRITY MISMATCH: File {filename}. Client: {client_sha256}, Backend: {backend_sha256}"
            )
            return {
                "status": "error",
                "message": f"Hash verification failed! Browser claimed [{client_sha256[:16]}...] but backend calculated [{backend_sha256[:16]}...]. Data corrupted in transit.",
                "client_sha256": client_sha256,
                "backend_sha256": backend_sha256
            }
        integrity_status = "VERIFIED_MATCH"
        cursor.execute("SELECT COUNT(*) FROM evidence")
        count = cursor.fetchone()[0]
        ev_id = f"EV-{datetime.datetime.now().year}-{count + 1:03d}"
        safe_name = f"{ev_id}_{backend_sha256[:12]}_{os.path.basename(filename)}"
        storage_path = os.path.join(EVIDENCE_VAULT_DIR, safe_name)
        with open(storage_path, "wb") as f:
            f.write(file_bytes)
        cursor.execute("""
            INSERT INTO evidence (
                id, incident_id, filename, filesize, filetype, stage, analyst,
                acquisition_method, host, client_sha256, backend_sha256, integrity_status,
                storage_path, acquisition_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev_id, incident_id or "CORP-GENERAL", filename, filesize, filetype, stage,
            analyst, acquisition_method, host, client_sha256, backend_sha256,
            integrity_status, storage_path, now
        ))
        conn.commit()

    add_audit_entry(
        actor=analyst,
        action="EVIDENCE_ACQUIRED",
        details=f"[{ev_id}] {filename} ({filesize} B) acquired from {host}. SHA-256: {backend_sha256[:24]}..."
    )
    return {
        "status": "success",
        "evidence_id": ev_id,
        "filename": filename,
        "filesize": filesize,
        "filetype": filetype,
        "stage": stage,
        "analyst": analyst,
        "host": host,
        "acquisition_method": acquisition_method,
        "client_sha256": client_sha256,
        "backend_sha256": backend_sha256,
        "integrity_status": integrity_status,
        "acquisition_time": now
    }

def get_evidence_list() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence ORDER BY acquisition_time DESC")
        return [dict(row) for row in cursor.fetchall()]

def log_soar_action(incident_id: str, playbook: str, action_name: str, action_type: str, command_input: str, execution_output: str, exit_code: int, approval_status: str, approved_by: Optional[str] = None) -> Dict[str, Any]:
    action_id = f"ACT-{hashlib.md5(f'{incident_id}_{action_name}_{utc_now()}'.encode()).hexdigest()[:8].upper()}"
    now = utc_now()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO soar_actions (
                id, incident_id, playbook, action_name, action_type, command_input,
                execution_output, exit_code, approval_status, approved_by, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            action_id, incident_id, playbook, action_name, action_type, command_input,
            execution_output, exit_code, approval_status, approved_by, now
        ))
        conn.commit()
    add_audit_entry(
        actor=approved_by or "SOAR_CONTROLLER",
        action="SOAR_ACTION_EXECUTED",
        details=f"[{action_id}] {action_name} ({action_type}) on {incident_id}. Exit: {exit_code}."
    )
    return {
        "id": action_id, "incident_id": incident_id, "playbook": playbook, "action_name": action_name,
        "action_type": action_type, "command_input": command_input, "execution_output": execution_output,
        "exit_code": exit_code, "approval_status": approval_status, "approved_by": approved_by, "timestamp": now
    }

def get_soar_actions(incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if incident_id:
            cursor.execute("SELECT * FROM soar_actions WHERE incident_id = ? ORDER BY timestamp DESC", (incident_id,))
        else:
            cursor.execute("SELECT * FROM soar_actions ORDER BY timestamp DESC")
        return [dict(row) for row in cursor.fetchall()]

init_db()
