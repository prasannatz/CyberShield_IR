# MICRO PROJECT - 15: DEVELOP AN INCIDENT RESPONSE PLAN FOR CYBER ATTACKS

**Academic Specialization:** Cyber Security & Information Assurance  
**Industry Focus:** Corporate IT (Enterprise Networks, Active Directory, Cloud, ERP, Remote Workforce)  
**Integrated Course Outcomes:**  
* **CO2:** Threat Analysis, Vulnerability Profiling, and Attack Classification  
* **CO4:** Incident Containment, Eradication, and Recovery Strategies  
* **CO5:** Digital Forensics, Evidence Preservation, Chain of Custody & Regulatory Audit  
**Standard Compliance:** NIST SP 800-61 Rev. 2, SANS PICERL, RFC 3227, ISO/IEC 27001, SOC 2 Type II, GDPR Art. 33, SEC Form 8-K  

---

## 1. Project Overview & Executive Summary

In enterprise **Corporate IT** ecosystems, organizations rely heavily on centralized identity infrastructure (Active Directory / Entra ID), Enterprise Resource Planning (ERP / CRM) systems, corporate file servers, multi-tenant cloud environments (M365, AWS, Azure), and hybrid remote access VPNs. A security incident targeting these foundational assets poses an existential threat to business continuity, corporate intellectual property (IP), confidential employee/customer PII, and corporate shareholder value.

The core objective of **Micro Project - 15** is to design, author, and deploy a structured **Enterprise Incident Response Plan (E-IRP)** and an interactive **Software Prototype (CyberShield-IR)** tailored specifically for **Corporate IT**. The system empowers corporate security operations center (SOC) analysts to detect intrusions, execute automated risk scoring (CO2), deploy surgical network/identity containment without triggering catastrophic business downtime (CO4), preserve court-admissible digital evidence under RFC 3227 (CO5), and satisfy enterprise regulatory reporting mandates (CO5).

### Key Performance Indicators (Corporate IT SLAs)
* **Mean Time to Detect (MTTD):** `< 5 minutes` across endpoint and cloud telemetry.
* **Mean Time to Contain (MTTC):** `< 15 minutes` for SEV-1 Critical corporate threats.
* **Recovery Time Objective (RTO):** `< 2 hours` for mission-critical Tier-0 Domain Controllers and ERP nodes.
* **Recovery Point Objective (RPO):** `0 data loss` via point-in-time transaction log replays and air-gapped immutable storage.

---

## 2. Integrated Course Outcomes (CO) Mapping

```
+---------------------------------------------------------------------------------------------------------------+
| Course Outcome   | Academic Objective                             | Implementation in CyberShield-IR          |
+------------------+------------------------------------------------+-------------------------------------------+
| CO2              | Threat Analysis & Attack Classification        | - Algorithmic 4-tier Severity Matrix      |
|                  |                                                | - Threat profiling for Enterprise         |
|                  |                                                |   Ransomware, Active Directory Attacks,   |
|                  |                                                |   M365 AiTM Phishing, and VPN Tunnel Abuse|
|                  |                                                | - Dynamic Risk Scoring Engine (0-100)     |
+------------------+------------------------------------------------+-------------------------------------------+
| CO4              | Containment, Eradication & Disaster Recovery   | - Segmented Host/VLAN Isolation           |
|                  |                                                | - KRBTGT Active Directory Double-Reset    |
|                  |                                                | - M365 OAuth Token Revocation             |
|                  |                                                | - Corporate VPN Kill-Switch & Step-Up MFA |
|                  |                                                | - Gold Master Rebuild & Ledger Replay     |
+------------------+------------------------------------------------+-------------------------------------------+
| CO5              | Digital Forensics, Audit & Regulatory Reporting| - RFC 3227 Order of Volatility Model      |
|                  |                                                | - Cryptographic SHA-256 Hash Auditing     |
|                  |                                                | - Court-admissible Chain of Custody logs  |
|                  |                                                | - Corporate 5-Whys Root Cause Analysis    |
|                  |                                                | - GDPR Art. 33, ISO 27001, SOC 2 Disclosures|
+---------------------------------------------------------------------------------------------------------------+
```

---

## 3. Incident Response Lifecycle Architecture (NIST SP 800-61 Rev. 2)

```mermaid
flowchart TD
    subgraph Phase 1: Preparation
        P1[Tier-0 Identity & Asset Tagging] --> P2[EDR & SIEM Enterprise Baseline]
        P2 --> P3[Corporate CSIRT Standing Roster]
    end

    subgraph Phase 2: Detection & Analysis (CO2)
        D1[Corporate Network & Cloud Telemetry] --> D2[Algorithmic Risk Scoring]
        D2 --> D3{Severity Threshold}
        D3 -->|Score >= 80| D4[SEV-1 War Room Activated]
        D3 -->|Score < 80| D5[Standard Incident Queue]
    end

    subgraph Phase 3: Containment (CO4)
        C1[Host/VLAN Micro-Isolation] --> C2[Active Memory Snapshot Capture]
        C2 --> C3[Identity Session Revocation]
    end

    subgraph Phase 4: Eradication & Recovery (CO4)
        E1[Persistence & Malware Purge] --> E2[WORM Backup Validation]
        E2 --> E3[Service Replay & Staged Re-Entry]
    end

    subgraph Phase 5: Post-Incident Review (CO5)
        R1[Forensic Chain of Custody Sealing] --> R2[Corporate Governance Disclosures]
        R2 --> R3[5-Whys RCA & Corrective Action Plan]
    end

    Phase 1 --> Phase 2
    Phase 2 --> Phase 3
    Phase 3 --> Phase 4
    Phase 4 --> Phase 5
    Phase 5 -.->|Feedback Loop| Phase 1
```

---

## 4. Threat Triage & Severity Classification (CO2)

The corporate triage engine calculates incident severity dynamically using an objective weighted formula:

$$\text{Risk Score} = W_{\text{Asset}} + W_{\text{Vector}} + W_{\text{Exposure}} + W_{\text{BlastRadius}}$$

* **Asset Criticality Weight ($W_{\text{Asset}}$):** Tier-0 Domain Controller / Identity (40), Enterprise ERP / CRM (25), Corporate Workstation Subnet (12), Non-critical staging server (5).
* **Corporate Attack Vector ($W_{\text{Vector}}$):** Enterprise Ransomware (35), Executive BEC / Token Theft (30), Compromised VPN Gateway (28), External Portal DDoS (18), Malicious Insider (15).
* **Business Impact Exposure ($W_{\text{Exposure}}$):** $> \$1\text{M}$ (20), $> \$500\text{k}$ (14), $> \$100\text{k}$ (8), $< \$100\text{k}$ (2).
* **Blast Radius Weight ($W_{\text{BlastRadius}}$):** Number of impacted systems $\times 2$ (capped at 10).

### Four-Tier Severity Matrix
1. **SEV-1 (Critical) [Score $\ge 80$]:** Active Domain Controller encryption, mass corporate ransomware outbreak, or enterprise cloud tenant takeover. SLA: `< 15 minutes`.
2. **SEV-2 (High) [Score $55 - 79$]:** Multi-workstation lateral movement, executive account takeover, or compromised remote VPN gateway. SLA: `< 30 minutes`.
3. **SEV-3 (Medium) [Score $30 - 54$]:** Isolated endpoint malware prevented by EDR, brute force login attempt blocked by perimeter WAF. SLA: `< 2 hours`.
4. **SEV-4 (Low) [Score $< 30$]:** Routine spam campaign, low-volume reconnaissance port scan on corporate perimeter. SLA: `< 8 hours`.

---

## 5. Technical Response Playbooks (CO4)

### Playbook 1: Corporate Ransomware & Active Directory Defense
1. **Surgical Isolation Without Powering Off:**
   - Apply switch ACLs to isolate corporate VLAN 10.
   - **Do not power down or reboot.** Power loss destroys encryption keys in volatile RAM and eliminates data recovery opportunities.
2. **Identity Invalidation:**
   - Execute dual password reset of the Active Directory `KRBTGT` account to revoke all Kerberos Golden/Silver tickets across domain controllers.
3. **Volatile Memory Preservation:**
   - Acquire full physical memory dump via WinPmem/FTK CLI to write-protected external storage.
4. **Zero-Loss Restoration:**
   - Verify immutable air-gapped WORM backups. Replay database write-ahead transaction logs up to the exact millisecond before encryption started.

### Playbook 2: Executive Business Email Compromise (BEC) & Cloud Session Takeover
1. **Sever Cloud Persistence:**
   - Invalidate all Microsoft 365 OAuth refresh tokens and terminate active session cookies using Microsoft Graph API.
   - Delete rogue inbox forwarding rules diverting emails with keywords `Invoice`, `Confidential`, `Executive` to external inboxes.
2. **Gateway Defense:**
   - Terminate active VPN tunnels and mandate FIDO2 hardware token verification for all administrative re-entry.

### Playbook 3: Corporate Perimeter DDoS & Application Flooding
1. **Traffic Scrubbing:**
   - Divert inbound traffic via BGP Anycast to upstream DDoS cloud scrubbers (Cloudflare / AWS Shield).
2. **Rate Limiting:**
   - Enforce 5 requests/sec thresholds on single sign-on (SSO) login portals and drop hostile ASN ranges.

---

## 6. Digital Forensics, RFC 3227 Order of Volatility & Governance (CO5)

### RFC 3227 Order of Volatility Hierarchy
When investigating corporate cyber incidents, evidence must be collected in order of decreasing volatility to preserve evidentiary integrity:
1. **CPU Registers & Cache:** Most volatile; destroyed immediately on power cutoff.
2. **Physical RAM / Memory:** Holds plaintext credentials, ransomware keys, and injected beacon DLLs.
3. **Network Sockets & ARP Cache:** Holds active C2 connections, internal pivot tunnels, and routing tables.
4. **Process Tables & Kernel Modules:** Running threads, parent-child process relationships, and DLL injections.
5. **Non-Volatile Storage (SAN/SSD):** File systems, persistence registries, corporate event logs.
6. **Remote Centralized Telemetry:** SIEM event logs and network firewall packet captures.

### Evidence Integrity & Chain of Custody (CoC)
All acquired items are hashed using **SHA-256** at the exact second of collection. Any modification changes the hash value, providing verifiable mathematical proof of non-tampering in court proceedings.

### Corporate Regulatory & Compliance Disclosures
* **GDPR Article 33:** Notification to the supervisory Data Protection Authority within `72 Hours` of awareness.
* **ISO/IEC 27001 / SOC 2:** Mandatory post-incident root cause documentation and control enhancement audit.
* **SEC Form 8-K:** Material cybersecurity incidents disclosed within `4 Business Days` for public corporations.
* **National CERT / Cyber Security Agency:** Critical infrastructure incident reporting within `6 Hours`.

---

## 7. Software Prototype Architecture & Execution Guide

The prototype consists of:
* `index.html`: Fully interactive, responsive SOC Dark Dashboard with real-time attack simulation, dynamic risk calculation, terminal console, and printable report exporter.
* `app.py`: High-performance Python backend server providing REST APIs for automated triage, playbooks, evidence logging, and audit tracking.
* `triage_cli.py`: Rapid terminal forensic collector illustrating RFC 3227 volatility capture, SHA-256 hashing, and compliance verification.
* `test_prototype.py`: Automated testing suite validating triage logic, playbook coverage, and hash algorithms.

### How to Run:
```bash
# 1. Run Automated Unit Tests
python test_prototype.py

# 2. Start the Backend & Web Dashboard
python app.py
# (Open your browser to: http://localhost:8080/index.html)

# 3. Run Live Forensic CLI Triage Tool
python triage_cli.py
```

---

## 8. Viva Voce Examination Questions & High-Scoring Answers

**Q1: How does your Incident Response Plan satisfy Course Outcome 2 (CO2)?**  
*Answer:* We implemented an algorithmic Threat Triage Matrix tailored for Corporate IT. It assesses asset criticality (such as Tier-0 Domain Controllers), attack vectors (ransomware, BEC, VPN tunneling), estimated enterprise financial impact, and impacted systems to calculate an objective 0–100 risk score and determine response SLAs (SEV-1 to SEV-4).

**Q2: In a corporate ransomware outbreak, why do you not immediately shut down the affected machines (CO4)?**  
*Answer:* Shutting down clears volatile RAM where the encryption keys and injected process beacons reside. Our plan uses host/VLAN network isolation so lateral movement is stopped while RAM is kept powered on for live memory forensic extraction.

**Q3: How does your plan handle evidence preservation and court admissibility (CO5)?**  
*Answer:* We strictly follow the RFC 3227 Order of Volatility, acquiring artifacts starting from CPU cache and physical RAM down to non-volatile disks. Each artifact is stamped with a SHA-256 cryptographic hash and tracked in an immutable Chain of Custody ledger documenting sequence, custodian identity, timestamp, and purpose of transfer.

**Q4: How do you achieve zero data loss (RPO: 0) during a database breach?**  
*Answer:* We combine air-gapped, immutable WORM backups with point-in-time transaction log replays. The incident response team identifies the exact microsecond of the breach cut-off, restores the clean snapshot, and replays valid committed transactions up to the millisecond preceding the malicious injection.
