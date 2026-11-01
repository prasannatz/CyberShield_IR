"""
================================================================================
  CyberShield IR - PowerPoint Presentation Generator
  Micro Project - 15: Incident Response Plan for Cyber Attacks (Corporate IT)
  Team: Prasanna Tudu, Nissy Pragna, Akshaya MK, Christeena Biju
================================================================================
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    # 16:9 Widescreen dimensions
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Colors
    c_navy    = RGBColor(7, 13, 26)       # #070d1a
    c_card    = RGBColor(13, 21, 38)      # #0d1526
    c_cyan    = RGBColor(56, 189, 248)    # #38bdf8
    c_red     = RGBColor(248, 113, 113)   # #f87171
    c_green   = RGBColor(52, 211, 153)    # #34d399
    c_amber   = RGBColor(251, 191, 36)    # #fbbf24
    c_white   = RGBColor(255, 255, 255)
    c_sub     = RGBColor(203, 213, 225)   # #cbd5e1
    c_muted   = RGBColor(148, 163, 184)   # #94a3b8

    def apply_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = c_navy
        bg.line.fill.background()
        return bg

    def add_header(slide, title, category="MICRO PROJECT - 15 | CORPORATE IT INCIDENT RESPONSE"):
        # Category tag
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = c_cyan

        # Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.5), Inches(0.8))
        tf = title_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(26)
        p.font.bold = True
        p.font.color.rgb = c_white

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 1: TITLE SLIDE
    # ─────────────────────────────────────────────────────────────────────────
    s1 = prs.slides.add_slide(blank_layout)
    apply_bg(s1)

    # Accent bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.2), Inches(0.15), Inches(4.8))
    bar.fill.solid()
    bar.fill.fore_color.rgb = c_cyan
    bar.line.fill.background()

    # Title text box
    tb1 = s1.shapes.add_textbox(Inches(1.2), Inches(1.1), Inches(11.0), Inches(2.2))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p0 = tf1.paragraphs[0]
    p0.text = "MICRO PROJECT - 15"
    p0.font.size = Pt(15)
    p0.font.bold = True
    p0.font.color.rgb = c_cyan

    p1 = tf1.add_paragraph()
    p1.text = "DEVELOP AN INCIDENT RESPONSE PLAN FOR CYBER ATTACKS"
    p1.font.size = Pt(32)
    p1.font.bold = True
    p1.font.color.rgb = c_white

    p2 = tf1.add_paragraph()
    p2.text = "Industry Focus: Corporate IT  |  Integrated COs: CO2, CO4, CO5"
    p2.font.size = Pt(18)
    p2.font.color.rgb = c_amber

    # Team Box Container
    team_card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.2), Inches(3.6), Inches(10.8), Inches(2.5))
    team_card.fill.solid()
    team_card.fill.fore_color.rgb = c_card
    team_card.line.color.rgb = c_cyan

    tb_team = s1.shapes.add_textbox(Inches(1.5), Inches(3.8), Inches(10.2), Inches(2.1))
    tf_team = tb_team.text_frame
    tf_team.word_wrap = True

    p_t0 = tf_team.paragraphs[0]
    p_t0.text = "PROJECT TEAM MEMBERS:"
    p_t0.font.size = Pt(13)
    p_t0.font.bold = True
    p_t0.font.color.rgb = c_cyan

    members = [
        ("Prasanna Tudu", "URK25DS3056"),
        ("Nissy Pragna", "URK25DS3055"),
        ("Akshaya MK", "URK25DS3033"),
        ("Christeena Biju", "URK25DS3022")
    ]
    for name, reg in members:
        p_m = tf_team.add_paragraph()
        p_m.text = f"•  {name}  —  {reg}"
        p_m.font.size = Pt(15)
        p_m.font.bold = True
        p_m.font.color.rgb = c_white

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 2: PROJECT OBJECTIVES & SCOPE
    # ─────────────────────────────────────────────────────────────────────────
    s2 = prs.slides.add_slide(blank_layout)
    apply_bg(s2)
    add_header(s2, "Executive Problem Statement & Project Scope")

    cards_data = [
        ("The Corporate IT Challenge", [
            "Modern corporate enterprises face targeted attacks: Ransomware, Active Directory Takeover, and M365 session theft.",
            "Traditional response (powering off) destroys volatile memory keys and halts enterprise operations.",
            "Average corporate cost of a data breach exceeds $4.45M."
        ], c_red, Inches(0.8)),
        ("Our Solution: CyberShield IR", [
            "Structured Incident Response Plan aligned with NIST SP 800-61 Rev.2.",
            "Automated triage engine with quantifiable risk metrics.",
            "Surgical containment playbooks that protect operational continuity.",
            "Court-admissible RFC 3227 forensic evidence vault."
        ], c_cyan, Inches(4.8)),
        ("Key Corporate SLAs & Goals", [
            "MTTD (Mean Time to Detect): < 5 minutes via SIEM/EDR.",
            "MTTC (Mean Time to Contain): < 15 minutes for SEV-1.",
            "RTO (Recovery Time Objective): < 2 hours for critical services.",
            "RPO (Recovery Point Objective): Zero data loss via immutable snapshots."
        ], c_green, Inches(8.8))
    ]

    for title, points, color, x in cards_data:
        box = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, Inches(1.7), Inches(3.7), Inches(5.0))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s2.shapes.add_textbox(x + Inches(0.2), Inches(1.9), Inches(3.3), Inches(4.6))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(18)
        p.font.bold = True
        p.font.color.rgb = color

        for pt in points:
            p_pt = tf.add_paragraph()
            p_pt.text = f"\n▸ {pt}"
            p_pt.font.size = Pt(13)
            p_pt.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 3: INTEGRATED COURSE OUTCOMES (CO) ALIGNMENT
    # ─────────────────────────────────────────────────────────────────────────
    s3 = prs.slides.add_slide(blank_layout)
    apply_bg(s3)
    add_header(s3, "Integrated Course Outcomes (CO) Mapping")

    co_data = [
        ("CO2: Threat Analysis & Risk Profiling", [
            "Asset Criticality Tiering (Tier-0 Domain Controllers, ERP clusters).",
            "Attack Vector Profiling (Ransomware, BEC, VPN Infiltration, DDoS).",
            "Algorithmic Risk Scoring Formula (0 to 100).",
            "4-Tier Severity Classification Matrix (SEV-1 through SEV-4)."
        ], c_amber, Inches(1.7)),
        ("CO4: Containment, Eradication & Recovery", [
            "Surgical host/VLAN network isolation (preventing lateral movement).",
            "Active Directory KRBTGT dual-reset (invalidating Kerberos Golden Tickets).",
            "M365 OAuth session purge & VPN gateway kill-switch.",
            "Point-in-time database transaction replay & Gold Master provisioning."
        ], c_cyan, Inches(3.4)),
        ("CO5: Forensics, Chain of Custody & Audit", [
            "RFC 3227 Order of Volatility adherence (RAM -> Sockets -> Disk).",
            "Cryptographic SHA-256 evidence integrity hashing.",
            "Court-admissible Chain of Custody (CoC) ledger tracking.",
            "Corporate 5-Whys Root Cause Analysis (RCA) & GDPR/ISO 27001 audit."
        ], c_green, Inches(5.1))
    ]

    for title, points, color, y in co_data:
        box = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), y, Inches(11.7), Inches(1.45))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s3.shapes.add_textbox(Inches(1.1), y + Inches(0.12), Inches(11.2), Inches(1.2))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = color

        p_pt = tf.add_paragraph()
        p_pt.text = "   • " + "   • ".join(points)
        p_pt.font.size = Pt(12)
        p_pt.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 4: CORPORATE IT THREAT LANDSCAPE
    # ─────────────────────────────────────────────────────────────────────────
    s4 = prs.slides.add_slide(blank_layout)
    apply_bg(s4)
    add_header(s4, "Corporate IT Attack Surface & Threat Vectors")

    threats = [
        ("Double-Extortion Ransomware", "Target: Core storage, file shares, SAN volumes\nImpact: Data encrypted + exfiltrated; business stoppage\nDetection: Volume shadow copy deletion (vssadmin.exe)", c_red, Inches(0.8), Inches(1.8)),
        ("Active Directory Takeover", "Target: Tier-0 Domain Controllers, Kerberos tickets\nImpact: Full administrative domain compromise\nDetection: Anomalous DCSync, Kerberoasting, Golden Tickets", c_amber, Inches(6.8), Inches(1.8)),
        ("M365 Phishing & Session Hijacking", "Target: Executive inboxes (CEO/CFO), SharePoint, OneDrive\nImpact: Adversary-in-the-Middle (AiTM) OAuth token theft\nDetection: Hidden forwarding rules, anomalous geo-logins", c_cyan, Inches(0.8), Inches(4.4)),
        ("Compromised Remote VPN & DDoS", "Target: Edge SSL-VPN concentrators, SSO login portals\nImpact: Unauthorized perimeter tunneling, service denial\nDetection: Credential stuffing spikes, brute force volume", c_green, Inches(6.8), Inches(4.4))
    ]

    for title, desc, color, x, y in threats:
        box = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(5.7), Inches(2.3))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s4.shapes.add_textbox(x + Inches(0.2), y + Inches(0.15), Inches(5.3), Inches(2.0))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(17)
        p.font.bold = True
        p.font.color.rgb = color

        for line in desc.split("\n"):
            p_l = tf.add_paragraph()
            p_l.text = f"• {line}"
            p_l.font.size = Pt(12)
            p_l.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 5: NIST SP 800-61 Rev.2 LIFECYCLE
    # ─────────────────────────────────────────────────────────────────────────
    s5 = prs.slides.add_slide(blank_layout)
    apply_bg(s5)
    add_header(s5, "Incident Response Lifecycle Architecture (NIST SP 800-61)")

    phases = [
        ("1. Preparation", ["Asset inventory & tiering", "SIEM/EDR baseline", "CSIRT war room readiness"], Inches(0.8)),
        ("2. Detection & Analysis", ["Telemetry correlation", "Risk scoring (0-100)", "Severity matrix assignment"], Inches(3.2)),
        ("3. Containment", ["VLAN micro-isolation", "RAM state preservation", "Session/token revocation"], Inches(5.6)),
        ("4. Eradication & Recovery", ["Malware purge", "WORM backup check", "Gold Master replay"], Inches(8.0)),
        ("5. Post-Incident Review", ["Chain of custody report", "5-Whys Root Cause Analysis", "Regulatory compliance"], Inches(10.4))
    ]

    for title, bullets, x in phases:
        box = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, Inches(2.0), Inches(2.1), Inches(4.6))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = c_cyan

        tb = s5.shapes.add_textbox(x + Inches(0.1), Inches(2.2), Inches(1.9), Inches(4.2))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = c_cyan

        for b in bullets:
            p_b = tf.add_paragraph()
            p_b.text = f"\n▸ {b}"
            p_b.font.size = Pt(12)
            p_b.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 6: ALGORITHMIC TRIAGE & SEVERITY (CO2)
    # ─────────────────────────────────────────────────────────────────────────
    s6 = prs.slides.add_slide(blank_layout)
    apply_bg(s6)
    add_header(s6, "Algorithmic Threat Triage & Severity Matrix (CO2)")

    # Formula Box
    f_box = s6.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(1.1))
    f_box.fill.solid()
    f_box.fill.fore_color.rgb = c_card
    f_box.line.color.rgb = c_amber

    tb_f = s6.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(11.3), Inches(0.9))
    tf_f = tb_f.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = "Risk Score Formula = W(Asset) + W(Vector) + W(Exposure) + W(BlastRadius)"
    p_f.font.size = Pt(18)
    p_f.font.bold = True
    p_f.font.color.rgb = c_amber

    p_f2 = tf_f.add_paragraph()
    p_f2.text = "Weights: Asset Tier (up to 40) + Attack Vector (up to 35) + Financial Impact (up to 20) + Systems Affected (up to 10)"
    p_f2.font.size = Pt(12)
    p_f2.font.color.rgb = c_sub

    # 4 Severity tiers
    tiers = [
        ("SEV-1: CRITICAL (Score >= 80)", "SLA: < 15 Minutes\nTriggers: Active Domain Controller encryption, mass corporate ransomware\nAction: Immediate War Room, CISO & Board escalation", c_red, Inches(3.2)),
        ("SEV-2: HIGH (Score 55 - 79)", "SLA: < 30 Minutes\nTriggers: Multi-workstation lateral pivot, executive account takeover\nAction: Core CSIRT engaged, subnet isolation", c_amber, Inches(4.2)),
        ("SEV-3: MEDIUM (Score 30 - 54)", "SLA: < 2 Hours\nTriggers: Isolated endpoint malware, perimeter brute force\nAction: Tier-2 SOC investigation, endpoint quarantine", c_cyan, Inches(5.2)),
        ("SEV-4: LOW (Score < 30)", "SLA: < 8 Hours\nTriggers: Routine spam campaigns, low-volume reconnaissance scans\nAction: Automated ticketing queue, standard analyst review", c_green, Inches(6.2))
    ]

    for title, desc, color, y in tiers:
        box = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), y, Inches(11.7), Inches(0.85))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s6.shapes.add_textbox(Inches(1.0), y + Inches(0.08), Inches(11.3), Inches(0.7))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"{title}   |   {desc.replace(chr(10), '  •  ')}"
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = color

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 7: PLAYBOOK A - RANSOMWARE & ACTIVE DIRECTORY (CO4)
    # ─────────────────────────────────────────────────────────────────────────
    s7 = prs.slides.add_slide(blank_layout)
    apply_bg(s7)
    add_header(s7, "Containment Playbook A: Ransomware & Active Directory (CO4)")

    steps_a = [
        ("Step 1: Network Quarantine (VLAN Isolation)", "Isolate infected subnet via switch ACLs. DO NOT POWER OFF. Maintaining power preserves encryption keys and injected process memory in volatile RAM.", c_red),
        ("Step 2: Kerberos KRBTGT Password Double-Reset", "Invalidate all Kerberos Golden/Silver tickets domain-wide across Active Directory to completely terminate attacker persistence.", c_amber),
        ("Step 3: Volatile Memory Acquisition (RFC 3227)", "Acquire 64GB live RAM bitstream image to write-blocked external storage. Enables key recovery and forensic timeline reconstruction.", c_cyan),
        ("Step 4: Verify Air-Gapped Immutable WORM Backups", "Validate air-gapped snapshots prior to infection cut-off timestamp. Ensures zero data loss (RPO: 0).", c_green),
        ("Step 5: Restore from Hardened Gold Master", "Deploy sanitized operating system image and replay verified transaction journals. Return production services online (RTO: < 2 hours).", c_white)
    ]

    for i, (title, desc, color) in enumerate(steps_a):
        y = Inches(1.7 + i * 1.05)
        box = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), y, Inches(11.7), Inches(0.95))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s7.shapes.add_textbox(Inches(1.1), y + Inches(0.08), Inches(11.2), Inches(0.8))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = color

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(12)
        p_d.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 8: PLAYBOOKS B & C - EMAIL & DDOS (CO4)
    # ─────────────────────────────────────────────────────────────────────────
    s8 = prs.slides.add_slide(blank_layout)
    apply_bg(s8)
    add_header(s8, "Containment Playbooks B & C: Email Hijacking & DDoS (CO4)")

    # Playbook B
    box_b = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.7), Inches(5.7), Inches(5.1))
    box_b.fill.solid()
    box_b.fill.fore_color.rgb = c_card
    box_b.line.color.rgb = c_amber

    tb_b = s8.shapes.add_textbox(Inches(1.1), Inches(1.9), Inches(5.2), Inches(4.7))
    tf_b = tb_b.text_frame
    tf_b.word_wrap = True
    p_b = tf_b.paragraphs[0]
    p_b.text = "Playbook B: M365 Email & VPN Defense"
    p_b.font.size = Pt(18)
    p_b.font.bold = True
    p_b.font.color.rgb = c_amber

    pts_b = [
        "Revoke M365 OAuth Tokens: Invalidate session cookies via Microsoft Graph API and enforce global sign-out.",
        "Purge Rogue Forwarding Rules: Delete attacker rules filtering confidential executive correspondence.",
        "Sever Compromised VPN Tunnels: Terminate remote access sessions immediately at perimeter gateway.",
        "Step-Up Authentication: Enforce FIDO2 hardware token verification for all administrative accounts.",
        "Executive Breach Notification: Dispatch formal incident disclosure to CISO and Corporate Legal Counsel."
    ]
    for pt in pts_b:
        p = tf_b.add_paragraph()
        p.text = f"\n▸ {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = c_sub

    # Playbook C
    box_c = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.7), Inches(5.7), Inches(5.1))
    box_c.fill.solid()
    box_c.fill.fore_color.rgb = c_card
    box_c.line.color.rgb = c_cyan

    tb_c = s8.shapes.add_textbox(Inches(7.1), Inches(1.9), Inches(5.2), Inches(4.7))
    tf_c = tb_c.text_frame
    tf_c.word_wrap = True
    p_c = tf_c.paragraphs[0]
    p_c.text = "Playbook C: Enterprise Perimeter DDoS Defense"
    p_c.font.size = Pt(18)
    p_c.font.bold = True
    p_c.font.color.rgb = c_cyan

    pts_c = [
        "BGP Anycast Route Shift: Divert perimeter traffic to upstream cloud scrubbing center (Cloudflare/AWS Shield).",
        "Layer-7 Rate Limiting: Enforce 5 requests/sec threshold on corporate single sign-on (SSO) login portals.",
        "Botnet & Hostile ASN Filtering: Automatically drop requests from anonymous proxies and known Tor exit nodes.",
        "Gateway Capacity Normalization: Edge infrastructure load returns to normal operating parameters within 5 minutes.",
        "WAF Rule Hardening: Permanent IP and subnet threat rules pushed across global web application firewalls."
    ]
    for pt in pts_c:
        p = tf_c.add_paragraph()
        p.text = f"\n▸ {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 9: FORENSICS & RFC 3227 ORDER OF VOLATILITY (CO5)
    # ─────────────────────────────────────────────────────────────────────────
    s9 = prs.slides.add_slide(blank_layout)
    apply_bg(s9)
    add_header(s9, "Digital Forensics & RFC 3227 Order of Volatility (CO5)")

    vol_steps = [
        ("Tier 1: CPU Registers & Cache", "Most volatile — destroyed immediately on power cut. Capture first.", c_red, Inches(1.8)),
        ("Tier 2: Physical RAM / Memory", "Holds active ransomware keys, plaintext credentials, and injected beacons.", c_amber, Inches(2.7)),
        ("Tier 3: Network Sockets & ARP Cache", "Captures live C2 communication channels and lateral movement pivot hops.", c_amber, Inches(3.6)),
        ("Tier 4: Process Trees & Kernel States", "Process hierarchy, DLL injections, and memory dump attempts.", c_cyan, Inches(4.5)),
        ("Tier 5: Non-Volatile Storage (SAN/SSD)", "Persistent registry run keys, encrypted files, and local event logs.", c_green, Inches(5.4)),
        ("Tier 6: Remote SIEM & Central Firewalls", "Centralized audit logs, NetFlow data, and perimeter firewall telemetry.", c_white, Inches(6.3))
    ]

    for title, desc, color, y in vol_steps:
        box = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), y, Inches(11.7), Inches(0.75))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s9.shapes.add_textbox(Inches(1.1), y + Inches(0.06), Inches(11.2), Inches(0.65))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"{title}   —   {desc}"
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = color

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 10: ROOT CAUSE ANALYSIS & COMPLIANCE (CO5)
    # ─────────────────────────────────────────────────────────────────────────
    s10 = prs.slides.add_slide(blank_layout)
    apply_bg(s10)
    add_header(s10, "Root Cause Analysis (5-Whys) & Regulatory Compliance (CO5)")

    # 5 Whys Box
    box_w = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.7), Inches(5.7), Inches(5.1))
    box_w.fill.solid()
    box_w.fill.fore_color.rgb = c_card
    box_w.line.color.rgb = c_red

    tb_w = s10.shapes.add_textbox(Inches(1.1), Inches(1.9), Inches(5.2), Inches(4.7))
    tf_w = tb_w.text_frame
    tf_w.word_wrap = True
    p_w = tf_w.paragraphs[0]
    p_w.text = "5-Whys Root Cause Analysis (RCA)"
    p_w.font.size = Pt(17)
    p_w.font.bold = True
    p_w.font.color.rgb = c_red

    whys = [
        "Why 1: File shares & Domain Controller encrypted at 14:02 UTC causing business outage.",
        "Why 2: Attacker used stolen local admin credentials to pivot laterally from workstation WS-042.",
        "Why 3: Workstation WS-042 compromised via spear-phishing macro opened by staff member.",
        "Why 4: Endpoint Detection and Response (EDR) policy was in 'Audit-Only' mode.",
        "Root Cause: Change management failure during network migration left new subnet EDR policy un-enforced."
    ]
    for w in whys:
        p = tf_w.add_paragraph()
        p.text = f"\n▸ {w}"
        p.font.size = Pt(11)
        p.font.color.rgb = c_sub

    # Compliance Box
    box_cmp = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.7), Inches(5.7), Inches(5.1))
    box_cmp.fill.solid()
    box_cmp.fill.fore_color.rgb = c_card
    box_cmp.line.color.rgb = c_green

    tb_cmp = s10.shapes.add_textbox(Inches(7.1), Inches(1.9), Inches(5.2), Inches(4.7))
    tf_cmp = tb_cmp.text_frame
    tf_cmp.word_wrap = True
    p_cmp = tf_cmp.paragraphs[0]
    p_cmp.text = "Corporate Regulatory Compliance"
    p_cmp.font.size = Pt(17)
    p_cmp.font.bold = True
    p_cmp.font.color.rgb = c_green

    cmps = [
        "GDPR Article 33: Mandatory notification within 72 Hours. Our response time: 3h 30m (Compliant).",
        "ISO/IEC 27001 & SOC 2: Mandatory root cause documentation, evidence tracking, and CAP remediation.",
        "SEC Form 8-K: Material cybersecurity incidents disclosed within 4 business days for public firms.",
        "National CERT: Emergency incident dispatch filed within mandatory 6-hour regulatory window.",
        "Court-Admissible Evidence: SHA-256 cryptographic hashes guarantee evidence integrity in litigation."
    ]
    for c in cmps:
        p = tf_cmp.add_paragraph()
        p.text = f"\n▸ {c}"
        p.font.size = Pt(12)
        p.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 11: SOFTWARE PROTOTYPE ARCHITECTURE
    # ─────────────────────────────────────────────────────────────────────────
    s11 = prs.slides.add_slide(blank_layout)
    apply_bg(s11)
    add_header(s11, "CyberShield-IR Software Prototype Architecture")

    proto_cards = [
        ("Web SOC Dashboard (index.html)", [
            "Built with Bootstrap 5 & high-contrast dark theme.",
            "Live simulated ransomware drill trigger.",
            "Interactive execution of Playbooks A, B, and C.",
            "RFC 3227 Order of Volatility evidence logging.",
            "Printable Post-Mortem & Audit report exporter."
        ], c_cyan, Inches(0.8)),
        ("Python REST API Engine (app.py)", [
            "Pure Python standard library (no heavy dependencies).",
            "POST /api/triage: Computes dynamic 0-100 risk score.",
            "POST /api/contain: Dispatches playbook actions.",
            "POST /api/evidence: Calculates SHA-256 hashes.",
            "Append-only audit trail logging."
        ], c_amber, Inches(4.8)),
        ("Forensic CLI Suite (triage_cli.py)", [
            "Runs 6 sequential incident response phases.",
            "Live system baseline & IP telemetry extraction.",
            "Order of Volatility cryptographic hashing.",
            "Exports court-admissible JSON CoC audit report.",
            "Ideal for live examination / viva demonstration."
        ], c_green, Inches(8.8))
    ]

    for title, points, color, x in proto_cards:
        box = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, Inches(1.8), Inches(3.7), Inches(4.9))
        box.fill.solid()
        box.fill.fore_color.rgb = c_card
        box.line.color.rgb = color

        tb = s11.shapes.add_textbox(x + Inches(0.2), Inches(2.0), Inches(3.3), Inches(4.5))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = color

        for pt in points:
            p_pt = tf.add_paragraph()
            p_pt.text = f"\n▸ {pt}"
            p_pt.font.size = Pt(12)
            p_pt.font.color.rgb = c_sub

    # ─────────────────────────────────────────────────────────────────────────
    # SLIDE 12: CONCLUSION & SUMMARY
    # ─────────────────────────────────────────────────────────────────────────
    s12 = prs.slides.add_slide(blank_layout)
    apply_bg(s12)

    box_end = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(1.2), Inches(10.3), Inches(5.1))
    box_end.fill.solid()
    box_end.fill.fore_color.rgb = c_card
    box_end.line.color.rgb = c_cyan

    tb_end = s12.shapes.add_textbox(Inches(1.8), Inches(1.5), Inches(9.7), Inches(4.5))
    tf_end = tb_end.text_frame
    tf_end.word_wrap = True

    p_e0 = tf_end.paragraphs[0]
    p_e0.text = "CONCLUSION & PROJECT SUMMARY"
    p_e0.font.size = Pt(28)
    p_e0.font.bold = True
    p_e0.font.color.rgb = c_cyan

    conclusions = [
        "Surgical Resilience: Demonstrated that modern incident response must isolate threats without shutting down systems or disrupting business operations.",
        "CO2 Achieved: Implemented an algorithmic threat classification matrix with deterministic response SLAs.",
        "CO4 Achieved: Developed actionable playbooks for Ransomware, Active Directory, M365 Email, and Perimeter DDoS.",
        "CO5 Achieved: Enforced RFC 3227 volatility capture, SHA-256 evidence hashing, and GDPR/ISO 27001 compliance.",
        "Fully Operational Prototype: Working web dashboard and CLI forensic tool running live on local infrastructure."
    ]

    for c in conclusions:
        p = tf_end.add_paragraph()
        p.text = f"\n✔ {c}"
        p.font.size = Pt(13)
        p.font.color.rgb = c_white

    p_thanks = tf_end.add_paragraph()
    p_thanks.text = "\nThank You!  —  Questions & Discussion"
    p_thanks.font.size = Pt(18)
    p_thanks.font.bold = True
    p_thanks.font.color.rgb = c_amber

    output_path = "CyberShield_IR_Presentation.pptx"
    prs.save(output_path)
    print(f"[+] Successfully generated PowerPoint deck: {output_path}")

if __name__ == "__main__":
    create_deck()

