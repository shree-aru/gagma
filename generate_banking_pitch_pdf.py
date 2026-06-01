import os
import sys
from fpdf import FPDF

class GAGMABankingPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(113, 128, 150)
            self.cell(0, 10, "GAGMA - Enterprise Banking Security Proposal", new_x="RIGHT", new_y="TOP", align="L")
            self.set_x(10)
            self.cell(0, 10, f"Page {self.page_no()}", new_x="LMARGIN", new_y="NEXT", align="R")
            self.set_draw_color(226, 232, 240)
            self.line(10, 18, 200, 18)
            self.ln(5)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(113, 128, 150)
            self.cell(0, 10, "STRICTLY CONFIDENTIAL - PREPARED FOR BANKING OPERATIONS", new_x="RIGHT", new_y="TOP", align="L")
            self.set_x(10)
            self.cell(0, 10, "Contact: http://3.229.117.157", new_x="LMARGIN", new_y="NEXT", align="R")

def create_banking_proposal():
    pdf = GAGMABankingPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # ── Page 1: CORPORATE COVER PAGE ────────────────────────
    pdf.add_page()
    
    # Large Decorative Left Stripe
    pdf.set_fill_color(11, 25, 44) # Dark Navy
    pdf.rect(0, 0, 8, 297, "F")
    
    # Accent Right Stripe
    pdf.set_fill_color(0, 136, 204) # Deep Blue
    pdf.rect(8, 0, 4, 297, "F")
    
    pdf.set_x(20)
    pdf.ln(40)
    
    # Badge
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(203, 97, 0) # Accent Amber
    pdf.cell(0, 10, "ENTERPRISE BUSINESS & TECHNICAL PROPOSAL", new_x="LMARGIN", new_y="NEXT")
    
    # Title
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 15, "GAGMA Platform", new_x="LMARGIN", new_y="NEXT")
    
    # Subtitle
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(74, 85, 104)
    pdf.cell(0, 10, "Securing Mobile Banking against Fraudulent APKs", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(15)
    
    # Executive Hook
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(26, 32, 44)
    hook_text = (
        "A highly scalable, Graph-Augmented Generative AI solution designed "
        "specifically for commercial banking ecosystems. GAGMA automates threat intelligence, "
        "reverse-engineers rogue APKs at machine speed, maps structural relationship trees, "
        "and proactively isolates digital payment and credential-stealing banking trojans."
    )
    pdf.set_x(20)
    pdf.multi_cell(175, 6, hook_text)
    
    pdf.ln(50)
    
    # Bottom Corporate Meta Panel
    pdf.set_draw_color(226, 232, 240)
    pdf.set_fill_color(247, 250, 252)
    pdf.rect(20, 175, 175, 55, "DF")
    
    pdf.set_y(179)
    pdf.set_x(24)
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 6, "PREPARED BY:", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(74, 85, 104)
    pdf.set_x(24)
    pdf.cell(0, 5, "GAGMA Engineering & Threat Intelligence Group", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(24)
    pdf.cell(0, 5, "Target Audience: Chief Information Security Officer (CISO) & Head of Fraud Operations", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(24)
    pdf.cell(0, 5, "Technical Standards: RBI Cyber Security Master Circular Aligned", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(24)
    pdf.cell(0, 5, "Deployment Architecture: Hybrid Cloud / On-Premise Sandbox API", new_x="LMARGIN", new_y="NEXT")

    # ── Page 2: BUSINESS VALUE CASE ─────────────────────────
    pdf.add_page()
    
    # Section Header
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "1. Executive Pitch & The Banking Value Case", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(3)
    
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(26, 32, 44)
    value_intro = (
        "Rogue Android APK files are currently the single most aggressive vector used by fraudsters "
        "targeting retail banking customers. Cybercriminals use SMS phishing, fake payment portals, and "
        "fraudulent customer service scams to trick users into installing malicious apps. Once installed, "
        "these trojans intercept SMS OTPs, overlay fake login sheets on legitimate banking apps, and bypass "
        "all multi-factor authentication protocols, executing unauthorized financial transfers."
    )
    pdf.multi_cell(0, 5.5, value_intro)
    pdf.ln(5)
    
    # Columns for Key Pillars
    pillars = [
        ("Preventative Financial Shield (ROI)", "Rather than reacting after fraud has taken place, GAGMA stops the threat at the customer's phone edge. By detecting and blocklisting fraudulent APKs, we stop credential and OTP theft before any transaction occurs, saving millions in customer fraud reimbursements."),
        ("Explainable AI Risk Appraisals", "Standard threat scanners flag software as suspicious without context. GAGMA's Graph-Augmented GenAI traces the precise call chains, explaining exactly which permissions, APIs, and domains are used to exfiltrate financial data, satisfying risk compliance requirements."),
        ("Unmatched Operational Velocity", "Manual analysis of a complex APK takes up to 48 hours for a skilled security analyst. GAGMA disassembles, maps to Neo4j, runs multi-agent code analysis, and produces CERT-In compliant reports in less than 60 seconds.")
    ]
    
    for title, desc in pillars:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 136, 204)
        pdf.cell(0, 6, f"- {title}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.multi_cell(0, 5, desc)
        pdf.ln(4)

    # ── Page 3: TECHNICAL STACK & SECURITY Compliance ────────
    pdf.add_page()
    
    # Section Header
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "2. Technical Architecture & Tech Stack", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(3)
    
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(26, 32, 44)
    tech_intro = (
        "GAGMA replaces outdated binary scanners with a modern, database-relational approach to code structure. "
        "By parsing variables and calls into an interconnected Neo4j graph database, we create a highly queryable "
        "knowledge representation of the threat."
    )
    pdf.multi_cell(0, 5.5, tech_intro)
    pdf.ln(5)
    
    # Tech Stack Table Representation
    tech_stack = [
        ("Layer / Component", "Technologies Used", "Business & Operational Function"),
        ("Static Analysis Engine", "jadx, apktool, androguard", "Headless disassembly of compiled DEX files to recover source structures."),
        ("Graph Knowledge Base", "Neo4j Enterprise / AuraDB", "Dynamic storage mapping class sequences and relationship paths."),
        ("GenAI Reasoning Core", "Google Gemini Pro / GPT APIs", "Autonomous code audit, de-obfuscation, and report translation."),
        ("API & Integration Gateway", "FastAPI, SQLite3, Caddy Server", "High-performance endpoint routers with auto-SSL routing."),
        ("CSO Response Interface", "HTML5, Vanilla CSS, Vis.js", "Glassmorphic dashboard showing call-graphs and phone overlays.")
    ]
    
    for layer, tech, func in tech_stack:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(0, 136, 204)
        pdf.cell(45, 6, layer, new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "I", 9.5)
        pdf.set_text_color(74, 85, 104)
        pdf.cell(50, 6, tech, new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(26, 32, 44)
        pdf.cell(95, 6, func, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        
    pdf.ln(6)
    
    # 3. Regulatory Compliance
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "3. Regulatory Compliance & RBI Security Standards", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(3)
    
    pdf.set_font("Helvetica", "", 10.5)
    compliance_intro = (
        "Digital safety mandates set by the Reserve Bank of India (RBI) require banks to take "
        "active measures to counter rogue applications and exfiltration attempts:"
    )
    pdf.multi_cell(0, 5.5, compliance_intro)
    pdf.ln(4)
    
    standards = [
        ("RBI Cybersecurity Circular (2023)", "GAGMA implements continuous automated threat scoring for newly emerged overlays, actively protecting APIs and credentials before release."),
        ("CERT-In SLA Framework", "Under current mandates, banks must disclose severe cyber incidents within 6 hours. GAGMA generates a formatted CERT-In incident log instantly on completion, saving valuable forensic hours."),
        ("NPCI Fraud Risk Management", "Enforces targeted protection overlays that specifically detect malicious hooks aiming to hijack UPI, Google Pay, PhonePe, and major commercial banking systems.")
    ]
    
    for standard_title, standard_desc in standards:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(203, 97, 0)
        pdf.cell(0, 6, standard_title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.multi_cell(0, 5, standard_desc)
        pdf.ln(3)

    # ── Page 4: BUSINESS ROI & ROADMAP ─────────────────────
    pdf.add_page()
    
    # Section Header
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "4. Commercial Implementation Roadmap", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(3)
    
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(26, 32, 44)
    roadmap_intro = (
        "Deploying GAGMA into your bank's ecosystem is structured into three seamless, non-disruptive phases "
        "designed to guarantee standard security without interfering with the bank's core banking system (CBS):"
    )
    pdf.multi_cell(0, 5.5, roadmap_intro)
    pdf.ln(5)
    
    phases = [
        ("Phase 1: Passive Threat-Intelligence Sandbox (Weeks 1 - 2)", "Establish a dedicated sandbox API endpoint. Ingest newly discovered APK binaries sent via threat-feeds or customer reports directly into the GAGMA sandbox. Run autonomous decompile and graph modeling without affecting any user-facing code."),
        ("Phase 2: Active SIEM & MDM Automated Containment (Weeks 3 - 4)", "Wire GAGMA's incident webhook outputs straight to the bank's Security Operations Center SIEM (e.g. Splunk or QRadar) and corporate Mobile Device Management (MDM). If a critical threat is mapped, trigger automated blocklists."),
        ("Phase 3: Cross-Channel Customer Alerting (Weeks 5 - 6)", "Activate GAGMA's redundant mobile gateway. When a malicious campaign targeting your bank's package name is validated, broadcast automated push alerts and blocklist rules to custom mobile apps, keeping customer devices safe.")
    ]
    
    for phase_title, phase_desc in phases:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 136, 204)
        pdf.cell(0, 6, phase_title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.multi_cell(0, 5, phase_desc)
        pdf.ln(4)
        
    pdf.ln(10)
    
    # Concluding CTA
    pdf.set_draw_color(0, 136, 204)
    pdf.set_fill_color(240, 248, 255)
    pdf.rect(10, 175, 190, 40, "DF")
    
    pdf.set_y(179)
    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 6, "PARTNER WITH GAGMA SECURITY SOLUTIONS", new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(74, 85, 104)
    pdf.set_x(14)
    pdf.cell(0, 5, "Bring the cutting-edge power of Graph-Augmented Generative AI to your banking ecosystem.", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_x(14)
    pdf.cell(0, 5, "Eliminate rogue APK threat loops, satisfy audit standards, and secure your digital perimeter.", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_x(14)
    pdf.cell(0, 5, "Schedule an Enterprise Integration Trial at: http://3.229.117.157", new_x="LMARGIN", new_y="NEXT", align="C")

    # Save PDF
    pdf.output("c:\\Users\\HP\\Downloads\\apps\\gagma\\gagma_banking_pitch_proposal.pdf")
    print("PDF Successfully generated at c:\\Users\\HP\\Downloads\\apps\\gagma\\gagma_banking_pitch_proposal.pdf")

if __name__ == "__main__":
    create_banking_proposal()
