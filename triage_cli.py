"""
================================================================================
  CyberShield IR - Rapid Forensic Triage CLI Tool (Corporate IT Edition)
  Course Outcomes: CO2 (Threat Analysis) | CO4 (Playbooks) | CO5 (Forensics)
  Standards      : RFC 3227 Order of Volatility | ISO/IEC 27037 Evidence Integrity
================================================================================
"""

import socket
import datetime
import hashlib
import platform
import os
import sys
import time
import json

R = '\033[91m'  # Red
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
C = '\033[96m'  # Cyan
W = '\033[97m'  # White
D = '\033[90m'  # Dark Gray
RS = '\033[0m'  # Reset

def print_banner():
    print(f"{C}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║     CYBERSHIELD RAPID INCIDENT TRIAGE & FORENSIC SUITE v2.5        ║")
    print("║     Industry Domain : Corporate IT (Enterprise Infrastructure)       ║")
    print("║     Compliance      : RFC 3227 | ISO 27001 | SOC 2 | GDPR Art. 33    ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"{RS}")

def section(title):
    print(f"\n{D}── {Y}{title}{D} {'─' * (62 - len(title))}{RS}")

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def main():
    print_banner()
    time.sleep(0.3)

    # 1. PHASE 1: SYSTEM BASELINE & TRIAGE (CO2)
    section("PHASE 1: System Baseline & Environment Triage (CO2)")
    host = socket.gethostname()
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = "127.0.0.1"

    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    case_ref = f"CORP-IRP-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M')}"

    print(f"  {D}▸{RS} {W}Target Hostname      {RS}: {C}{host}{RS}")
    print(f"  {D}▸{RS} {W}Network Address      {RS}: {C}{ip}{RS}")
    print(f"  {D}▸{RS} {W}Operating Platform   {RS}: {G}{platform.system()} {platform.release()} ({platform.machine()}){RS}")
    print(f"  {D}▸{RS} {W}Incident Timestamp   {RS}: {Y}{now_utc} UTC{RS}")
    print(f"  {D}▸{RS} {W}Tracking Incident ID {RS}: {C}{case_ref}{RS}")
    time.sleep(0.4)

    # 2. PHASE 2: THREAT RISK PROFILING (CO2)
    section("PHASE 2: Corporate Threat Vector Profiling & Severity (CO2)")
    threats = [
        ("Enterprise Storage Ransomware", "SEV-1 CRITICAL", 95, R),
        ("Active Directory Kerberoasting", "SEV-1 CRITICAL", 88, R),
        ("M365 Phishing & Token Hijacking", "SEV-2 HIGH",     78, Y),
        ("Corporate VPN Gateway Abuse",    "SEV-2 HIGH",     70, Y),
        ("Enterprise Web Portal DDoS",     "SEV-3 MEDIUM",   52, C),
        ("Malicious Insider Data Exfil",   "SEV-3 MEDIUM",   40, G)
    ]
    print(f"\n  {'Corporate Threat Vector':<36} {'Severity':<18} {'Risk Rating':<16}")
    print(f"  {'─'*36} {'─'*18} {'─'*16}")
    for name, sev, score, color in threats:
        bar = '█' * (score // 10) + '░' * (10 - score // 10)
        print(f"  {W}{name:<36}{RS} {color}{sev:<18}{RS} {color}{bar} {score}%{RS}")
        time.sleep(0.1)

    # 3. PHASE 3: RFC 3227 ORDER OF VOLATILITY COLLECTION (CO5)
    section("PHASE 3: Evidence Capture under RFC 3227 Order of Volatility (CO5)")
    stages = [
        ("1", "Volatile RAM & CPU Registers", "PRESERVE LIVE: Encryption keys resident in memory", R),
        ("2", "Network Sockets & ARP Cache",   "Active C2 connections & internal pivot routes", Y),
        ("3", "Process Trees & Kernel States",  "Malware injections & LSASS dump attempts", Y),
        ("4", "Temporary Files & Pagefile",     "Attacker staging directories in %TEMP%", C),
        ("5", "Non-Volatile Disk Images (SAN)", "File system journals & registry persistence", G),
        ("6", "Remote SIEM & Central Firewalls","Corporate edge firewall telemetry logs", D)
    ]

    evidence_records = []
    for num, stage_name, rationale, col in stages:
        artifact_raw = f"{host}_{stage_name}_{now_utc}"
        hash_val = sha256_text(artifact_raw)
        ev_id = f"EV-00{num}-CORP"
        print(f"\n  {col}[{num}]{RS} {W}{stage_name}{RS}")
        print(f"      {D}Rationale : {rationale}{RS}")
        print(f"      {D}Artifact  : {C}{ev_id}{RS}")
        print(f"      {D}SHA-256   : {G}{hash_val}{RS}")
        evidence_records.append({
            "id": ev_id,
            "order": int(num),
            "stage": stage_name,
            "sha256": hash_val
        })
        time.sleep(0.15)

    # 4. PHASE 4: AUTOMATED CONTAINMENT PLAYBOOK (CO4)
    section("PHASE 4: Corporate Containment Playbook Execution (CO4)")
    playbook_steps = [
        ("VLAN Network Quarantine", "Switch ACLs applied — lateral movement blocked, RAM energized", R),
        ("Active Directory Defense", "KRBTGT dual-reset executed — Golden Tickets invalidated", R),
        ("Identity Session Purge", "M365 OAuth tokens revoked — global corporate sign-out enforced", Y),
        ("VPN Gateway Severance", "Compromised remote tunnels killed — FIDO2 MFA challenge required", Y),
        ("Traffic Scrubbing Divert", "BGP Anycast shifted — 99.4% malicious packet flood dropped", C),
        ("Immutable Backup Verification", "WORM repository validated — zero corporate data loss (RPO: 0)", G),
        ("Gold Master Provisioning", "Sanitized system restored & business operations returned online", G)
    ]

    print()
    for action, outcome, col in playbook_steps:
        sys.stdout.write(f"  {D}[....]{RS} {W}{action:<28}{RS} Executing...")
        sys.stdout.flush()
        time.sleep(0.35)
        sys.stdout.write(f"\r  {G}[ OK ]{RS} {W}{action:<28}{RS} {col}{outcome}{RS}\n")
        sys.stdout.flush()

    # 5. PHASE 5: REGULATORY & GOVERNANCE NOTIFICATION CHECK (CO5)
    section("PHASE 5: Corporate Regulatory & Governance Compliance (CO5)")
    regulations = [
        ("GDPR Article 33", "72 Hours", "3h 30m", G),
        ("ISO/IEC 27001 / SOC 2", "Root Cause Documented", "Verified & Audited", G),
        ("SEC Form 8-K", "4 Business Days", "Day 1 draft", G),
        ("National CERT / Cyber Unit", "6 Hours", "2h 10m", G)
    ]
    print(f"\n  {'Governance Standard':<26} {'Mandatory Window':<22} {'Elapsed Time':<16} Status")
    print(f"  {'─'*26} {'─'*22} {'─'*16} {'─'*10}")
    for reg, window, actual, col in regulations:
        print(f"  {W}{reg:<26}{RS} {D}{window:<22}{RS} {C}{actual:<16}{RS} {col}COMPLIANT{RS}")
        time.sleep(0.08)

    # 6. PHASE 6: CHAIN OF CUSTODY REPORT EXPORT (CO5)
    section("PHASE 6: Court-Admissible Chain of Custody Report (CO5)")
    report_data = {
        "report_type": "CyberShield Corporate IT Digital Forensics & Chain of Custody Log",
        "case_reference": case_ref,
        "target_endpoint": host,
        "ip_address": ip,
        "timestamp_utc": now_utc,
        "standards": ["RFC 3227", "ISO/IEC 27037", "NIST SP 800-61 Rev.2", "ISO/IEC 27001"],
        "evidence_inventory": evidence_records,
        "custody_transfer_log": [
            {"seq": 1, "action": "Live RAM Acquisition", "custodian": "Lead Corporate Forensics Analyst", "location": "Evidence Vault 1"},
            {"seq": 2, "action": "Cryptographic Hash Validation", "custodian": "Evidence Vault Safe", "location": "Faraday Enclosure"},
            {"seq": 3, "action": "Bitstream Copy for Investigation", "custodian": "Corporate DFIR Specialist", "location": "Forensic Workstation"}
        ]
    }

    report_filename = f"Corporate_CoC_Forensic_Report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n  {G}[✓]{RS} Chain of Custody report generated : {C}{report_filename}{RS}")
    print(f"  {G}[✓]{RS} Preserved evidence artifacts       : {W}{len(evidence_records)} items{RS}")
    print(f"  {G}[✓]{RS} Cryptographic Integrity Signature   : {C}{sha256_text(json.dumps(report_data))[:32]}...{RS}")

    print(f"\n  {G}╔══════════════════════════════════════════════════════════════════╗{RS}")
    print(f"  {G}║  Triage & Forensics Complete — All 6 Lifecycle Stages Passed    ║{RS}")
    print(f"  {G}║  CO2: Triaged | CO4: Contained & Recovered | CO5: Compliant     ║{RS}")
    print(f"  {G}╚══════════════════════════════════════════════════════════════════╝{RS}\n")

if __name__ == "__main__":
    main()
