# CyberShield IR — Enterprise Incident Response Platform

An automated, enterprise-grade Security Operations Center (SOC) incident response and digital forensics management platform designed for modern corporate IT infrastructure.

CyberShield IR bridges the gap between high-level incident response frameworks and rapid, automated technical execution. The platform enables corporate security teams to detect intrusions, calculate real-time algorithmic risk scores, execute surgical containment playbooks without causing operational downtime, and preserve court-admissible forensic evidence.

---

## 🏛️ Architecture & Core Modules

The platform is designed around the **NIST SP 800-61 Rev. 2** lifecycle and adheres to **RFC 3227** guidelines for evidentiary data integrity:

```
+-------------------------------------------------------------------------------------------------------+
|                                    CYBERSHIELD IR PLATFORM ARCHITECTURE                               |
+-------------------------------------------------------------------------------------------------------+
|  1. THREAT TRIAGE ENGINE              | Dynamic risk scoring formula evaluating asset criticality,     |
|                                       | attack vectors, financial exposure, and blast radius.         |
|---------------------------------------+---------------------------------------------------------------|
|  2. SOAR PLAYBOOK ORCHESTRATION       | Surgical containment actions: VLAN quarantine, Active         |
|                                       | Directory KRBTGT dual-reset, M365 session invalidation, BGP.  |
|---------------------------------------+---------------------------------------------------------------|
|  3. DIGITAL FORENSICS & INTEGRITY     | Adheres to RFC 3227 Order of Volatility with live SHA-256      |
|                                       | cryptographic evidence hashing and Chain of Custody logging.  |
|---------------------------------------+---------------------------------------------------------------|
|  4. AUDIT & REGULATORY REPORTING      | Automated 5-Whys Root Cause Analysis and compliance tracking  |
|                                       | for GDPR Art. 33 (72h), ISO/IEC 27001, SOC 2, and SEC 8-K.   |
+-------------------------------------------------------------------------------------------------------+
```

---

## ⚡ Service Level Agreements (SLAs) & Benchmarks

* **Mean Time to Detect (MTTD):** `< 5 minutes` across endpoint and cloud telemetry streams.
* **Mean Time to Contain (MTTC):** `< 15 minutes` for critical enterprise security incidents.
* **Recovery Time Objective (RTO):** `< 2 hours` for Tier-0 Domain Controllers and core ERP nodes.
* **Recovery Point Objective (RPO):** `0 data loss` achieved via point-in-time transaction log replays and air-gapped immutable storage.

---

## 📁 Repository Structure

```text
CyberShield_IR/
├── index.html                     # Full-featured SOC Dashboard (Dark Theme, Simulator, Exporter)
├── app.py                         # Enterprise REST API & Automation Server (Python)
├── triage_cli.py                  # Command-Line Forensic Acquisition & Triage Suite
├── test_prototype.py              # Automated Unit & Integration Test Suite
├── presentation.html              # Interactive Slide Deck for Executive / Stakeholder Briefings
├── CyberShield_IR_Presentation.pptx # Standalone 16:9 Presentation Deck (.pptx)
├── open_dashboard.bat             # 1-Click Browser Launcher (Standalone Mode)
├── run.bat                        # 1-Click Server & Web Dashboard Launcher
└── run_triage.bat                 # 1-Click Terminal Forensic Demonstration
```

---

## 🚀 Deployment & Usage

### 1. Standalone Browser Mode (Zero Dependency)
Double-click `open_dashboard.bat` or open `index.html` directly in any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox). All UI components, algorithmic scoring engines, and reporting generators run client-side.

### 2. Full-Stack Server Mode
To run the centralized REST API server and append-only audit trail logging:

```bash
# Start backend server
python app.py
```
*Access the Web SOC Dashboard:* `http://localhost:8080/index.html`

### 3. Automated Test Suite
To verify system integrity, severity matrix calculation, and cryptographic algorithms:

```bash
python test_prototype.py
```

### 4. Forensic Command-Line Suite
To execute an automated multi-phase forensic assessment and generate an RFC 3227 Chain of Custody JSON record:

```bash
python triage_cli.py
```

---

## 🛡️ Response Playbooks

### Playbook A: Corporate Ransomware & Active Directory Defense
1. **Network Quarantine (VLAN Isolation):** Restricts network communication at switch/firewall layer while keeping host AC power energized to preserve encryption keys and memory-resident malware beacons in volatile RAM.
2. **Active Directory Defense:** Executes dual password resets of the `KRBTGT` service account to invalidate all Kerberos Golden and Silver tickets domain-wide.
3. **Volatile Memory Acquisition:** Captures physical memory dumps to write-blocked storage media prior to disk tampering.
4. **Immutable Storage Validation:** Verifies pre-compromise snapshots within write-once-read-many (WORM) storage.
5. **Gold Master Rebuild:** Provisions hardened machine images and replays transaction logs up to the cut-off timestamp.

### Playbook B: Executive M365 Email Compromise & VPN Tunneling
1. **OAuth Session Purge:** Revokes all active enterprise refresh tokens and terminates active browser session cookies via Microsoft Graph API.
2. **Inbox Rule Sanitization:** Identifies and deletes hidden forwarding rules routing confidential correspondence to external endpoints.
3. **Perimeter Tunnel Severance:** Terminates active remote access sessions on perimeter SSL-VPN gateways and enforces step-up FIDO2 hardware token MFA.

### Playbook C: Perimeter DDoS & Application Flooding
1. **BGP Route Shift:** Diverts ingress edge traffic to upstream Anycast cloud scrubbing nodes (Cloudflare Magic Transit, AWS Shield).
2. **Layer-7 Rate Limiting:** Enforces 5 req/s thresholds on authentication and single sign-on (SSO) endpoints.
3. **Botnet Filtering:** Drops requests originating from anonymous proxies, Tor exit nodes, and known hostile Autonomous System Numbers (ASNs).

---

## ⚖️ Evidence Integrity & Chain of Custody

The platform maintains strict compliance with **RFC 3227** and **ISO/IEC 27037**:
* **Order of Volatility Execution:**
  $$\text{CPU Registers / Cache} \longrightarrow \text{Physical RAM} \longrightarrow \text{Network Sockets / ARP} \longrightarrow \text{Process State} \longrightarrow \text{Disk Storage} \longrightarrow \text{Remote Telemetry}$$
* **Cryptographic Verification:** Every evidence artifact is fingerprinted with an immediate **SHA-256** cryptographic hash upon acquisition.
* **Audit Trail:** An append-only ledger logs the timestamp, custodian identity, releasing authority, and transfer rationale for all forensic assets.

---

## 📜 Compliance & Regulatory Alignments

* **GDPR Article 33:** Automates disclosure timelines and incident reporting within the statutory **72-hour** notification window.
* **ISO/IEC 27001 & SOC 2 Type II:** Provides documented incident logs, 5-Whys Root Cause Analysis (RCA), and verifiable Corrective Action Plans (CAP).
* **SEC Form 8-K:** Formulates material cybersecurity incident disclosure documentation within the required 4-business-day timeframe.
