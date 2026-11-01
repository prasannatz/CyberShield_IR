"""
================================================================================
  CyberShield IR - Enterprise Incident Response Engine (Corporate IT Edition)
  Industry Focus : Corporate IT (Active Directory, ERP, M365, Cloud, VPN)
  Standards      : NIST SP 800-61 Rev.2 | SANS PICERL | ISO/IEC 27001 | SOC 2 | GDPR
  Course Outcomes: CO2 (Threat Analysis) | CO4 (Containment/Recovery) | CO5 (Forensics)
================================================================================
"""

import http.server
import socketserver
import json
import hashlib
import datetime
import os
import sys

PORT = 8080
LOG_FILE = "incident_audit_trail.log"
INCIDENTS = []
EVIDENCE = []

def utc_now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def write_audit(action: str, details: str):
    """Logs tamper-evident audit records into an append-only log file."""
    timestamp = utc_now()
    entry = f"[{timestamp} UTC] [{action.upper():18s}] {details}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
    print(entry.strip())

def calculate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# CO2: CORPORATE THREAT TRIAGE & RISK SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def score_threat(asset: str, vector: str, cost: int, systems: int) -> dict:
    """
    Evaluates incident impact based on Corporate IT asset criticality,
    attack vector profile, estimated enterprise exposure, and blast radius.
    """
    score = 0
    # Corporate Asset Criticality
    asset_map = {"critical": 40, "high": 25, "medium": 12, "low": 5}
    score += asset_map.get(asset, 5)

    # Vector weights in Corporate IT
    vector_map = {"ransomware": 35, "bec": 30, "vpn": 28, "ddos": 18, "insider": 15}
    score += vector_map.get(vector, 10)

    # Financial / Business exposure
    if cost > 1_000_000:
        score += 20
    elif cost > 500_000:
        score += 14
    elif cost > 100_000:
        score += 8
    else:
        score += 2

    # Systems blast radius
    score += min(systems * 2, 10)

    # Severity classification
    if score >= 80:
        return {"level": "SEV-1 CRITICAL", "sla": "< 15 minutes", "score": score}
    elif score >= 55:
        return {"level": "SEV-2 HIGH", "sla": "< 30 minutes", "score": score}
    elif score >= 30:
        return {"level": "SEV-3 MEDIUM", "sla": "< 2 hours", "score": score}
    else:
        return {"level": "SEV-4 LOW", "sla": "< 8 hours", "score": score}

# ─────────────────────────────────────────────────────────────────────────────
# CO4: CORPORATE CONTAINMENT & REMEDIATION PLAYBOOKS
# ─────────────────────────────────────────────────────────────────────────────
PLAYBOOKS = {
    "ransomware": [
        "Corporate VLAN 10 Network Quarantine applied — switch ACLs isolate target host while preserving RAM.",
        "KRBTGT dual-reset sequence executed across Active Directory domain controllers to revoke Kerberos tickets.",
        "Volatile memory dump acquired via WinPmem to write-protected forensic storage.",
        "Immutable enterprise backup snapshot validated at pre-incident cut-off point (RPO: 0 loss).",
        "Clean Hardened Gold Master OS provisioned & ERP database transaction journals replayed."
    ],
    "bec": [
        "M365 OAuth refresh tokens revoked & global session sign-out enforced for targeted executive account.",
        "Hidden inbox forwarding rules routing emails to external drop inboxes identified and purged.",
        "Azure Active Directory Conditional Access policy updated to mandate FIDO2 hardware MFA tokens.",
        "Corporate security disclosure dispatched to CISO, Legal Counsel, and Corporate Board."
    ],
    "vpn": [
        "Compromised corporate VPN sessions terminated immediately at edge firewall / concentrator.",
        "Attacker IP addresses and anomalous geo-locations added to perimeter firewall drop lists.",
        "Internal Active Directory service accounts rotated and audited for unauthorized privilege escalation.",
        "Remote access gateway access logs extracted for lateral movement timeline analysis."
    ],
    "ddos": [
        "BGP Anycast routing diverted to upstream enterprise cloud DDoS scrubbing center.",
        "WAF aggressive rate-limiting enforced (5 req/sec threshold on corporate single sign-on / login portals).",
        "Hostile proxy networks, Tor exit nodes, and attacker ASN blocks dropped at edge boundary."
    ]
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP SERVER & REST API DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────
class CyberShieldRequestHandler(http.server.SimpleHTTPRequestHandler):

    def send_json_response(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def parse_json_payload(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)
        return json.loads(raw_body.decode("utf-8")) if raw_body else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        # API: Return all incidents
        if self.path == "/api/incidents":
            self.send_json_response({"incidents": INCIDENTS, "count": len(INCIDENTS)})
        # API: Return all evidence
        elif self.path == "/api/evidence":
            self.send_json_response({"evidence": EVIDENCE, "count": len(EVIDENCE)})
        # API: Return audit trail
        elif self.path == "/api/audit":
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                self.send_json_response({"log": lines[-50:], "total": len(lines)})
            except FileNotFoundError:
                self.send_json_response({"log": [], "total": 0})
        # Default: Serve frontend files (index.html, etc.)
        else:
            if self.path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        data = self.parse_json_payload()

        # CO2: Automated Corporate Triage Engine
        if self.path == "/api/triage":
            title = data.get("title", "Unnamed Corporate Incident")
            asset = data.get("asset", "medium")
            vector = data.get("vector", "ransomware")
            cost = int(data.get("cost", 0))
            systems = int(data.get("systems", 1))

            result = score_threat(asset, vector, cost, systems)
            case_id = f"CORP-{1000 + len(INCIDENTS):04d}"
            incident_record = {
                "id": case_id,
                "title": title,
                "asset": asset,
                "vector": vector,
                "cost": cost,
                "systems": systems,
                "severity": result["level"],
                "sla": result["sla"],
                "score": result["score"],
                "timestamp": utc_now(),
                "status": "Assessed"
            }
            INCIDENTS.append(incident_record)
            write_audit("CO2-TRIAGE", f"[{case_id}] {title} evaluated to {result['level']} (Score: {result['score']}/100)")
            self.send_json_response({"status": "success", "case_id": case_id, **result})

        # CO4: Playbook Execution
        elif self.path == "/api/contain":
            vector = data.get("vector", "ransomware")
            case_id = data.get("case_id", "CORP-UNKNOWN")
            steps = PLAYBOOKS.get(vector, ["Generic corporate containment sequence executed."])
            for i, step in enumerate(steps, 1):
                write_audit("CO4-CONTAIN", f"[{case_id}] Step {i}: {step}")
            self.send_json_response({"status": "success", "case_id": case_id, "playbook": vector, "steps": steps})

        # CO5: Forensic Evidence Logger
        elif self.path == "/api/evidence":
            item = data.get("item", "Artifact")
            stage = data.get("stage", "Volatile RAM")
            analyst = data.get("analyst", "Corporate DFIR Analyst")
            host = data.get("host", "CORP-HOST01")

            hash_val = calculate_sha256(f"{item}_{host}_{utc_now()}")
            ev_id = f"EV-{len(EVIDENCE) + 1:03d}"
            evidence_record = {
                "id": ev_id,
                "item": item,
                "stage": stage,
                "analyst": analyst,
                "host": host,
                "sha256": hash_val,
                "timestamp": utc_now()
            }
            EVIDENCE.append(evidence_record)
            write_audit("CO5-FORENSICS", f"Acquired evidence {item} ({stage}) with SHA-256: {hash_val[:20]}...")
            self.send_json_response({"status": "success", "record": evidence_record})

        else:
            self.send_json_response({"error": "Endpoint not found"}, 404)

    def log_message(self, fmt, *args):
        # Suppress noisy default console requests; audit log takes precedence
        pass

if __name__ == "__main__":
    print("=" * 70)
    print("  CYBERSHIELD IR - CORPORATE IT INCIDENT RESPONSE SYSTEM")
    print(f"  Web Dashboard : http://localhost:{PORT}/index.html")
    print(f"  Triage API    : POST http://localhost:{PORT}/api/triage")
    print(f"  Contain API   : POST http://localhost:{PORT}/api/contain")
    print(f"  Evidence API  : POST http://localhost:{PORT}/api/evidence")
    print(f"  Audit Trail   : GET  http://localhost:{PORT}/api/audit")
    print("=" * 70)
    write_audit("SYSTEM_START", f"Corporate Incident Response Server operational on port {PORT}")
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", PORT), CyberShieldRequestHandler) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server gracefully.")
        write_audit("SYSTEM_STOP", "Server terminated by operator.")
        sys.exit(0)
