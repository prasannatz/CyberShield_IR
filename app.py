"""
================================================================================
  CyberShield IR - Technical Incident Response & DFIR Backend Engine
  Standards: RFC 3227 (Order of Volatility) | ISO/IEC 27037 (Digital Evidence)
             NIST SP 800-61 Rev.2 (Incident Handling) | MITRE ATT&CK Mapping
================================================================================
"""

import http.server
import socketserver
import json
import base64
import os
import sys
import urllib.parse
from typing import Dict, Any

from database import (
    init_db,
    utc_now,
    add_audit_entry,
    verify_audit_chain,
    get_audit_trail,
    save_incident,
    get_incidents,
    save_evidence_record,
    get_evidence_list,
    log_soar_action,
    get_soar_actions,
    get_db_connection
)
from detection_engine import (
    calculate_risk_score,
    analyze_security_logs,
    evaluate_detection_benchmark,
    DETECTION_RULES
)

PORT = 8080
MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB Limit

# Structured SOAR Playbook Definitions with Simulated vs Real Action Typing & Sensitivity
STRUCTURED_PLAYBOOKS = {
    "ransomware": [
        {
            "step_id": "RW-01",
            "name": "Network Switch VLAN 10 Isolation",
            "type": "SIMULATED_INTEGRATION",
            "target": "Cisco Nexus 9300 Core Switch",
            "command": "conf t ; interface vlan 10 ; ip access-group ACL-IR-QUARANTINE in ; end",
            "sensitive": True,
            "rationale": "Quarantines target subnet to halt lateral spread while keeping host powered to preserve volatile RAM per RFC 3227.",
            "output": "VLAN 10 ACL-IR-QUARANTINE bound successfully. Inbound/Outbound user traffic dropped; forensic management port 22 preserved.",
            "exit_code": 0
        },
        {
            "step_id": "RW-02",
            "name": "Active Directory KRBTGT Dual-Reset",
            "type": "SIMULATED_INTEGRATION",
            "target": "CORP-DC01.corp.enterprise.local",
            "command": "Reset-KrbTgtAccountPassword.ps1 -Mode TwoCycle -Confirm:$false",
            "sensitive": True,
            "rationale": "Invalidates all forged Golden Tickets across Kerberos Key Distribution Center (KDC).",
            "output": "KRBTGT generation key cycle 1 completed. Second cycle scheduled (10h replication delay). Golden Tickets revoked.",
            "exit_code": 0
        },
        {
            "step_id": "RW-03",
            "name": "Volatile Memory Bitstream Acquisition",
            "type": "REAL_LOCAL_INTEGRATION",
            "target": "Target Host Physical RAM",
            "command": "winpmem_mini_x64.exe -o mem_dump.raw --volume_mode 1",
            "sensitive": False,
            "rationale": "Captures live encryption keys and injected DLLs prior to reboot under RFC 3227 Step 1.",
            "output": "Physical RAM image stream completed (16,384 MB). Output written to write-blocker attached vault. SHA-256 seal initialized.",
            "exit_code": 0
        },
        {
            "step_id": "RW-04",
            "name": "Immutable Backup Snapshot Verification",
            "type": "SIMULATED_INTEGRATION",
            "target": "Enterprise WORM Storage Repository",
            "command": "aws s3api get-object-legal-hold --bucket corp-immutable-backups --key 2026-10-31-snapshot.vhdx",
            "sensitive": False,
            "rationale": "Verifies that pre-attack snapshots are intact and protected by write-once-read-many (WORM) policies.",
            "output": "Legal hold: ON. ObjectLock retention: 365 Days. Zero malware modification detected in backup stream (RPO: 0).",
            "exit_code": 0
        }
    ],
    "bec": [
        {
            "step_id": "BEC-01",
            "name": "M365 OAuth Token Revocation & Global Sign-Out",
            "type": "SIMULATED_INTEGRATION",
            "target": "Microsoft Entra ID (Azure AD)",
            "command": "Revoke-AzureADUserAllRefreshToken -ObjectId cfo@enterprise.local",
            "sensitive": True,
            "rationale": "Immediately terminates adversary session cookie and token replay on hijacked executive account.",
            "output": "HTTP 200 OK: All user refresh tokens and active browser sessions terminated worldwide.",
            "exit_code": 0
        },
        {
            "step_id": "BEC-02",
            "name": "Purge Hidden Inbox Forwarding Rules",
            "type": "SIMULATED_INTEGRATION",
            "target": "Exchange Online",
            "command": "Get-InboxRule -Mailbox cfo@enterprise.local | Where-Object {$_.ForwardTo} | Remove-InboxRule -Confirm:$false",
            "sensitive": False,
            "rationale": "Disables attacker surveillance rule forwarding incoming financial communications to external drop inboxes.",
            "output": "Rule 'AutoForward_External_Wire' deleted from CFO mailbox.",
            "exit_code": 0
        }
    ],
    "vpn": [
        {
            "step_id": "VPN-01",
            "name": "Sever Compromised Remote VPN Sessions",
            "type": "SIMULATED_INTEGRATION",
            "target": "Palo Alto GlobalProtect Concentrator",
            "command": "request global-protect-gateway user-logout gateway-name GP-GW-01 user compromised_user",
            "sensitive": False,
            "rationale": "Terminates rogue tunnel connection and invalidates perimeter credentials.",
            "output": "Tunnel terminated. Client IP 198.51.100.42 dropped from active state table.",
            "exit_code": 0
        }
    ],
    "ddos": [
        {
            "step_id": "DOS-01",
            "name": "BGP Anycast Cloud Scrubbing Diversion",
            "type": "SIMULATED_INTEGRATION",
            "target": "Edge Border Routers (AS65001)",
            "command": "router bgp 65001 ; neighbor 198.51.100.1 route-map SCRUB-DIVERT out",
            "sensitive": True,
            "rationale": "Shifts inbound transit traffic to DDoS scrubbing center to absorb volumetric SYN floods.",
            "output": "BGP route announcement updated. Scrubbing center scrubbing 48.7 Gbps syn-flood traffic. 99.8% drop of malicious packets.",
            "exit_code": 0
        }
    ]
}


class CyberShieldHandler(http.server.SimpleHTTPRequestHandler):

    def send_json(self, data: Dict[str, Any], status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Analyst-ID")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message: str, status: int = 400, code: str = "BAD_REQUEST"):
        self.send_json({"status": "error", "code": code, "message": message}, status=status)

    def parse_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_UPLOAD_SIZE:
            raise ValueError("Payload size exceeds maximum allowed limit (25 MB).")
        raw_body = self.rfile.read(content_length)
        if not raw_body:
            return {}
        return json.loads(raw_body.decode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Analyst-ID")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. API: List all persistent incidents
        if path == "/api/incidents":
            incidents = get_incidents()
            self.send_json({"status": "success", "incidents": incidents, "count": len(incidents)})

        # 2. API: List all persistent evidence records
        elif path == "/api/evidence":
            evidence = get_evidence_list()
            self.send_json({"status": "success", "evidence": evidence, "count": len(evidence)})

        # 3. API: Cryptographic Audit Chain Records
        elif path == "/api/audit":
            records = get_audit_trail(limit=50)
            self.send_json({"status": "success", "audit_chain": records, "count": len(records)})

        # 4. API: Cryptographic Chain Integrity Verification
        elif path == "/api/audit/verify":
            verification = verify_audit_chain()
            self.send_json({"status": "success", "verification": verification})

        # 5. API: Security Telemetry Events
        elif path == "/api/events":
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 50")
                events = [dict(r) for r in cursor.fetchall()]
            self.send_json({"status": "success", "events": events, "count": len(events)})

        # 6. API: Detection Rules & Metrics
        elif path == "/api/detection/rules":
            benchmark = evaluate_detection_benchmark()
            self.send_json({"status": "success", "rules": DETECTION_RULES, "benchmark_metrics": benchmark})

        # 7. API: SOAR Playbook Actions Log
        elif path == "/api/soar/actions":
            actions = get_soar_actions()
            self.send_json({"status": "success", "actions": actions, "count": len(actions)})

        # 8. API: Playbook Definitions
        elif path == "/api/playbooks":
            self.send_json({"status": "success", "playbooks": STRUCTURED_PLAYBOOKS})

        # Default: Serve frontend static files
        else:
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        analyst_header = self.headers.get("X-Analyst-ID", "Analyst Desk")

        try:
            data = self.parse_json_body()
        except ValueError as e:
            self.send_error_json(str(e), status=413, code="PAYLOAD_TOO_LARGE")
            return
        except Exception as e:
            self.send_error_json(f"Malformed JSON request: {str(e)}", status=400, code="INVALID_JSON")
            return

        # ─────────────────────────────────────────────────────────────────────
        # 1. API: Quantitative Threat Triage & Incident Registration
        # ─────────────────────────────────────────────────────────────────────
        if path == "/api/triage":
            title = str(data.get("title", "")).strip()
            if not title:
                self.send_error_json("Field 'title' is required.", status=422, code="VALIDATION_ERROR")
                return

            asset = str(data.get("asset", "medium")).lower().strip()
            vector = str(data.get("vector", "ransomware")).lower().strip()

            try:
                cost = int(data.get("cost", 0))
                systems = int(data.get("systems", 1))
            except (ValueError, TypeError):
                self.send_error_json("'cost' and 'systems' must be valid integers.", status=422, code="VALIDATION_ERROR")
                return

            cost = max(0, cost)
            systems = max(1, systems)

            risk_eval = calculate_risk_score(asset, vector, cost, systems)
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM incidents")
                count = cursor.fetchone()[0]

            case_id = f"CORP-{1000 + count + 1}"
            analyst = data.get("analyst") or analyst_header

            incident_record = {
                "id": case_id,
                "title": title,
                "asset": asset,
                "vector": vector,
                "cost": cost,
                "systems": systems,
                "severity": risk_eval["level"],
                "sla": risk_eval["sla"],
                "score": risk_eval["score"],
                "status": "Assessed / Queued",
                "analyst": analyst,
                "detection_rule": data.get("detection_rule", "MANUAL-TRIAGE")
            }

            saved_id = save_incident(incident_record)
            self.send_json({
                "status": "success",
                "incident": incident_record,
                "risk_evaluation": risk_eval
            })

        # ─────────────────────────────────────────────────────────────────────
        # 2. API: Real Backend SHA-256 Forensic Evidence Upload & Verification
        # ─────────────────────────────────────────────────────────────────────
        elif path == "/api/evidence/upload":
            filename = str(data.get("filename", "")).strip()
            file_base64 = data.get("file_base64", "")
            client_sha256 = str(data.get("client_sha256", "")).strip().lower()

            if not filename:
                self.send_error_json("Field 'filename' is required.", status=422, code="VALIDATION_ERROR")
                return

            if not file_base64:
                self.send_error_json("Field 'file_base64' is required.", status=422, code="VALIDATION_ERROR")
                return

            try:
                file_bytes = base64.b64decode(file_base64)
            except Exception as e:
                self.send_error_json(f"Base64 decoding failed: {str(e)}", status=400, code="INVALID_BASE64")
                return

            stage = str(data.get("stage", "Volatile Memory (RAM)"))
            analyst = str(data.get("analyst") or analyst_header)
            host = str(data.get("host", "CORP-ENDPOINT01"))
            acquisition_method = str(data.get("acquisition_method", "Browser W3C File Stream"))
            incident_id = data.get("incident_id")

            result = save_evidence_record(
                filename=filename,
                file_bytes=file_bytes,
                client_sha256=client_sha256,
                stage=stage,
                analyst=analyst,
                host=host,
                acquisition_method=acquisition_method,
                incident_id=incident_id
            )

            if result.get("status") == "error":
                self.send_json(result, status=409)
            elif result.get("status") == "duplicate":
                self.send_json(result, status=200)
            else:
                self.send_json(result, status=201)

        # ─────────────────────────────────────────────────────────────────────
        # 3. API: Run Detection Engine Against Security Telemetry
        # ─────────────────────────────────────────────────────────────────────
        elif path == "/api/detection/run":
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM security_events ORDER BY id ASC")
                events = [dict(r) for r in cursor.fetchall()]

            alerts = analyze_security_logs(events)
            benchmark = evaluate_detection_benchmark()

            add_audit_entry(
                actor=analyst_header,
                action="DETECTION_RUN",
                details=f"Evaluated {len(events)} telemetry events against rules. Generated {len(alerts)} alerts."
            )

            self.send_json({
                "status": "success",
                "events_analyzed": len(events),
                "alerts": alerts,
                "benchmark_evaluation": benchmark
            })

        # ─────────────────────────────────────────────────────────────────────
        # 4. API: Execute SOAR Playbook Action (with Approval Gate)
        # ─────────────────────────────────────────────────────────────────────
        elif path == "/api/contain/execute":
            vector = str(data.get("vector", "ransomware")).lower()
            step_id = str(data.get("step_id", "")).upper()
            incident_id = str(data.get("incident_id", "CORP-GENERAL"))
            analyst = data.get("analyst") or analyst_header

            # Find step definition
            steps = STRUCTURED_PLAYBOOKS.get(vector, [])
            matching_step = next((s for s in steps if s["step_id"] == step_id), None)

            if not matching_step:
                self.send_error_json(f"Step ID '{step_id}' not found in playbook '{vector}'.", status=404, code="NOT_FOUND")
                return

            # Check if sensitive and needs approval
            if matching_step["sensitive"] and not data.get("confirmed"):
                self.send_json({
                    "status": "pending_approval",
                    "step_id": step_id,
                    "name": matching_step["name"],
                    "action_type": matching_step["type"],
                    "message": f"SENSITIVE ACTION GATE: {matching_step['name']} will impact enterprise connectivity. Explicit operator confirmation required.",
                    "command": matching_step["command"]
                }, status=200)
                return

            # Log executed action
            logged_action = log_soar_action(
                incident_id=incident_id,
                playbook=vector,
                action_name=matching_step["name"],
                action_type=matching_step["type"],
                command_input=matching_step["command"],
                execution_output=matching_step["output"],
                exit_code=matching_step["exit_code"],
                approval_status="APPROVED_AND_EXECUTED",
                approved_by=analyst
            )

            self.send_json({
                "status": "success",
                "action": logged_action
            })

        else:
            self.send_error_json(f"Endpoint '{path}' not found.", status=404, code="NOT_FOUND")

    def log_message(self, fmt, *args):
        # Suppress noisy standard HTTP access lines; the cryptographic audit trail logs all security actions
        pass


if __name__ == "__main__":
    init_db()
    print("=" * 76)
    print("  CYBERSHIELD IR - DFIR & INCIDENT RESPONSE PLATFORM (ENHANCED)")
    print("  Standards  : RFC 3227 Volatility | ISO/IEC 27037 Evidence Integrity")
    print("  Persistence: SQLite Storage (cybershield.db)")
    print("  Audit Chain: Cryptographically Hash-Linked (SHA-256 Tamper-Evident)")
    print("-" * 76)
    print(f"  Web Dashboard  : http://localhost:{PORT}/index.html")
    print(f"  Triage API     : POST http://localhost:{PORT}/api/triage")
    print(f"  Evidence Upload: POST http://localhost:{PORT}/api/evidence/upload")
    print(f"  Audit Verify   : GET  http://localhost:{PORT}/api/audit/verify")
    print(f"  Detection API  : POST http://localhost:{PORT}/api/detection/run")
    print("=" * 76)

    add_audit_entry("SYSTEM_INITIALIZER", "SERVER_START", f"CyberShield IR Server listening on port {PORT}")
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", PORT), CyberShieldHandler) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server gracefully.")
        add_audit_entry("SYSTEM_INITIALIZER", "SERVER_STOP", "Server shut down cleanly by operator.")
        sys.exit(0)
