# CyberShield IR — Enterprise Incident Response Platform

An automated, enterprise-grade Security Operations Center (SOC) incident response and digital forensics management platform designed for modern corporate IT infrastructure.

CyberShield IR bridges the gap between high-level incident response frameworks and rapid, automated technical execution. The platform enables corporate security teams to detect intrusions, calculate real-time quantitative risk scores, execute surgical containment playbooks without causing operational downtime, and preserve court-admissible forensic evidence.

---

## 🏛️ System Architecture & Implementation Transparency

To ensure strict academic and technical credibility, the architecture explicitly distinguishes between **implemented software capabilities** and **simulated threat telemetry models**:

```
+--------------------------------------------------------------------------------------------------------------------+
|                                      CYBERSHIELD IR SYSTEM ARCHITECTURE                                            |
+--------------------------------------------------------------------------------------------------------------------+
|  LAYER               | TECHNOLOGY STACK              | STATUS              | CAPABILITIES                          |
+----------------------+-------------------------------+---------------------+---------------------------------------+
|  1. Presentation     | HTML5, CSS3, Bootstrap 5.3,   | 100% Implemented    | High-contrast responsive SOC UI, live |
|     & Dashboard      | Vanilla JavaScript, FontAwesome|                    | evidence verification, report exporter|
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  2. Cryptographic    | W3C Web Crypto (Browser) &   | 100% Implemented    | Real client/server SHA-256 byte digest|
|     Integrity Engine | Python hashlib.sha256         |                     | calculation and hash-match check.     |
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  3. Quantitative     | Multi-factor weighted formula | 100% Implemented    | Computes deterministic 0-100 risk score|
|     Triage Engine    | in JavaScript & Python        |                     | and assigns response SLAs (SEV-1..4). |
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  4. Forensic Vault   | In-memory & JSON file ledger  | 100% Implemented    | RFC 3227 Order of Volatility tracking |
|     & Chain of Custody| (triage_cli.py & index.html) |                     | with ISO/IEC 27037 transfer logs.     |
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  5. Backend API      | Python 3 Standard Library     | 100% Implemented    | REST API endpoints (/api/triage,      |
|     Micro-Server     | (http.server, socketserver)   |                     | /api/contain, /api/evidence, /api/audit)|
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  6. Threat Telemetry | Synthetic Enterprise Traces   | Simulated Model     | EDR process trees, SIEM correlations, |
|     & Detection Logs | (LockBit 3.0, AiTM, DDoS)     |                     | and honeytoken triggers.              |
|----------------------+-------------------------------+---------------------+---------------------------------------+
|  7. SOAR Automation  | Script Command Orchestration  | Simulated SOAR      | Shows exact shell commands, inputs,   |
|     Playbooks        | (Cisco ACLs, KRBTGT, WinPmem) |                     | execution exit codes, and audit logs. |
+--------------------------------------------------------------------------------------------------------------------+
```

---

## 🔍 How Incidents Are Detected

Incidents in CyberShield IR are not merely displayed—they are driven by simulated multi-sensor detection pipelines modeling modern corporate security operations:

1. **Endpoint Detection & Response (EDR):** Detects process anomalies such as `svchost.exe` spawning `vssadmin.exe delete shadows /all /quiet` or `bcdedit.exe /set {default} recoveryenabled No` (T1490: Inhibit System Recovery).
2. **SIEM Correlation Rules:** Correlates multiple SMB (Port 445) authentications originating from anomalous internal workstations toward Tier-0 Domain Controllers using harvested administrator tokens (T1021.002: SMB/Windows Admin Shares).
3. **Active Directory Honeytokens:** Detects unauthorized Kerberos pre-authentication requests on fake administrator accounts (`svc_sql_admin`), exposing attacker reconnaissance.

---

## 🧮 Quantitative Risk Scoring Model

Incident severity is computed objectively using a weighted four-factor formula:

$$\text{Risk Score} = W_{\text{Asset}} + W_{\text{Vector}} + W_{\text{Exposure}} + W_{\text{BlastRadius}}$$

* **Asset Criticality ($W_{\text{Asset}}$, max 40):** Tier-0 Domain Controller = 40, Enterprise ERP/CRM = 25, Workstation Subnet = 12, Staging VM = 5.
* **Attack Vector Profile ($W_{\text{Vector}}$, max 35):** Double-Extortion Ransomware = 35, M365 AiTM Email Compromise = 30, Remote VPN Tunnel Infiltration = 28, Layer-7 DDoS = 18, Malicious Insider = 15.
* **Financial Exposure ($W_{\text{Exposure}}$, max 20):** $> \$1\text{M} = 20$, $> \$500\text{k} = 14$, $> \$100\text{k} = 8$, $< \$100\text{k} = 2$.
* **Blast Radius ($W_{\text{BlastRadius}}$, max 10):** $\text{Impacted Systems} \times 2$ (capped at 10).

### Four-Tier Severity Matrix & SLAs:
* **SEV-1 (Critical) [Score $\ge 80$]:** Response SLA `< 15 minutes`. Immediate War Room activation.
* **SEV-2 (High) [Score $55 - 79$]:** Response SLA `< 30 minutes`. Core CSIRT containment.
* **SEV-3 (Medium) [Score $30 - 54$]:** Response SLA `< 2 hours`. Tier-2 SOC endpoint quarantine.
* **SEV-4 (Low) [Score $< 30$]:** Response SLA `< 8 hours`. Standard analyst review queue.

---

## 🔬 Real Cryptographic Evidence Verification (RFC 3227 & ISO/IEC 27037)

The forensic suite strictly adheres to international evidentiary standards:
* **Real File Hashing:** In the **Forensics** tab, users select any actual file from their local drive. The platform calculates the genuine cryptographic SHA-256 byte digest in real-time using the native W3C Web Cryptography API (`crypto.subtle.digest`).
* **Integrity Match Verification:** Users can paste an expected SHA-256 hash to automatically test whether evidence has remained authentic or has suffered bit-level corruption/tampering.
* **RFC 3227 Order of Volatility:** Evidence is captured in decreasing order of fragility:
  $$\text{Tier 1: Volatile Memory (RAM)} \longrightarrow \text{Tier 2: Network Sockets} \longrightarrow \text{Tier 3: Process Tables} \longrightarrow \text{Tier 4: Disk Images} \longrightarrow \text{Tier 5: Remote SIEM Logs}$$
* **ISO/IEC 27037 Chain of Custody:** Every acquired artifact is logged with timestamp, custodian identity, source host, purpose of transfer, and verified SHA-256 digest.

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
├── index.html                     # Full-featured SOC Dashboard (Real SHA-256 Engine, Architecture, Simulator)
├── app.py                         # Enterprise REST API & Automation Server (Python)
├── triage_cli.py                  # Command-Line Forensic Acquisition & Triage Suite
├── test_prototype.py              # Automated Unit & Integration Test Suite
├── presentation.html              # Interactive Slide Deck for Executive / Stakeholder Briefings
├── CyberShield_IR_Presentation.pptx # Standalone 16:9 Presentation Deck (.pptx)
├── open_dashboard.bat             # 1-Click Browser Launcher (Standalone Mode)
├── run.bat                        # 1-Click Server & Web Dashboard Launcher
├── run_triage.bat                 # 1-Click Terminal Forensic Demonstration
└── push_to_github.bat             # Automated GitHub Push Wizard
```

---

## 🚀 Deployment & Usage

### 1. Standalone Browser Mode (Zero Dependency)
Double-click `open_dashboard.bat` or open `index.html` directly in any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox). All UI components, genuine Web Crypto SHA-256 calculation, and reporting engines run client-side.

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

## 🛡️ Response Playbooks (Simulated Orchestration)

To prevent accidental destruction of production infrastructure during demonstrations, playbook executions run in **Simulation Mode**, logging the exact commands, inputs, and exit codes:

* **Playbook A (Ransomware & Active Directory):** Executes switch ACL quarantine on VLAN 10 (keeps AC power energized for RAM triage), KRBTGT dual password reset, live WinPmem RAM dumping, and WORM storage verification.
* **Playbook B (M365 Email & VPN):** Executes Graph API OAuth token invalidation, malicious inbox rule purging, VPN tunnel termination, and FIDO2 step-up challenges.
* **Playbook C (Perimeter DDoS):** Diverts BGP Anycast routes to upstream cloud scrubbers, enforces 5 req/s rate limits on login endpoints, and drops hostile proxy ASNs.

---

## 📜 Compliance & Regulatory Alignments

* **GDPR Article 33:** Automates disclosure timelines and incident reporting within the statutory **72-hour** notification window.
* **ISO/IEC 27001 & SOC 2 Type II:** Provides documented incident logs, 5-Whys Root Cause Analysis (RCA), and verifiable Corrective Action Plans (CAP).
* **SEC Form 8-K:** Formulates material cybersecurity incident disclosure documentation within the required 4-business-day timeframe.
