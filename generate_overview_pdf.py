import os
import sys
from fpdf import FPDF

class GAGMAPDF(FPDF):
    def header(self):
        # We only want headers on page 2 and onwards (skip on cover page)
        if self.page_no() > 1:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(113, 128, 150)
            self.cell(0, 10, "GAGMA Project Overview - PSB Cybersecurity Hackathon 2026", new_x="RIGHT", new_y="TOP", align="L")
            self.set_x(10) # Reset x to alignment
            self.cell(0, 10, f"Page {self.page_no()}", new_x="LMARGIN", new_y="NEXT", align="R")
            self.set_draw_color(226, 232, 240)
            self.line(10, 18, 200, 18)
            self.ln(5)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(113, 128, 150)
            self.cell(0, 10, "Aligned with RBI IT Framework | CERT-In Incident Response Guidelines", new_x="RIGHT", new_y="TOP", align="L")
            self.set_x(10)
            self.cell(0, 10, "Host: http://3.229.117.157", new_x="LMARGIN", new_y="NEXT", align="R")

def create_overview_pdf():
    pdf = GAGMAPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # ── Page 1: COVER PAGE ──────────────────────────────────
    pdf.add_page()
    
    # Elegant Top Bar
    pdf.set_fill_color(0, 136, 204) # Deep Blue
    pdf.rect(0, 0, 210, 15, "F")
    
    pdf.ln(45)
    
    # Badge
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(0, 136, 204)
    pdf.cell(0, 10, "PSB CYBERSECURITY, FRAUD AND AI HACKATHON 2026", new_x="LMARGIN", new_y="NEXT", align="L")
    
    # Title
    pdf.set_font("Helvetica", "B", 38)
    pdf.set_text_color(11, 25, 44) # Dark Navy
    pdf.cell(0, 15, "GAGMA", new_x="LMARGIN", new_y="NEXT", align="L")
    
    # Subtitle
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(74, 85, 104)
    pdf.cell(0, 10, "Graph-Augmented GenAI Malware Analyst", new_x="LMARGIN", new_y="NEXT", align="L")
    
    pdf.ln(10)
    
    # Short description
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(26, 32, 44)
    desc_text = (
        "An enterprise-grade, Generative AI-powered Android APK malware reverse engineering, "
        "call-graph database modeler, and incident response orchestration gateway. Specifically "
        "engineered for the Indian digital banking and financial payments ecosystem."
    )
    pdf.multi_cell(0, 6, desc_text)
    
    pdf.ln(45)
    
    # Meta Box
    pdf.set_draw_color(226, 232, 240)
    pdf.set_fill_color(247, 250, 252)
    pdf.rect(10, 160, 190, 48, "DF")
    
    pdf.set_y(164)
    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 6, "PROJECT METADATA", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(74, 85, 104)
    pdf.set_x(14)
    pdf.cell(0, 5, "Problem Statement: PS1 - Generative AI-Based Automated Analysis of Fraudulent APKs", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 5, "Target Frameworks: RBI IT & Cybersecurity Framework | CERT-In Compliance SLA", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 5, "Source Repository: https://github.com/shree-aru/gagma.git", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.cell(0, 5, "Live Demo Server: http://3.229.117.157", new_x="LMARGIN", new_y="NEXT")

    # ── Page 2: CONTENT ─────────────────────────────────────
    pdf.add_page()
    
    # 1. Executive Summary
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "1. Executive Summary & Core Challenge", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(2)
    
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(26, 32, 44)
    summary_p1 = (
        "Modern digital banking platforms face a highly aggressive wave of mobile malware attacks. "
        "Fraudulent Android applications (APKs) targeting digital payment platforms like UPI, net banking, "
        "and credentials are systematically distributed via messaging networks, SMS phishing, and fake landing pages. "
        "These apps exfiltrate SMS OTP codes, display spoofed login screens, and hijack customer accounts."
    )
    pdf.multi_cell(0, 6, summary_p1)
    pdf.ln(4)
    
    summary_p2 = (
        "Traditional static analysis is too slow and depends heavily on skilled cyber professionals. "
        "GAGMA solves this resource gap by combining advanced reverse engineering, dynamic graph-database "
        "modeling (Neo4j Call-Graphs), and specialized multi-agent Generative AI. This automated pipeline "
        "recovers method calling sequences, queries call-graphs, flags banking risk indicators, and dispatches "
        "instant incident response notifications across enterprise networks in under 60 seconds."
    )
    pdf.multi_cell(0, 6, summary_p2)
    pdf.ln(6)
    
    # 2. Pipeline Workflow
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. System Pipeline & Technical Workflow", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(2)
    
    workflow_steps = [
        ("Step 1: Automated Decompilation", "The frontend FastAPI receives the raw APK file. In the backend, a headless decompiler using 'jadx' disassembles compiled dex files, extracting manifest permissions, resource paths, and recovering readable Java classes."),
        ("Step 2: Neo4j Call-Graph Ingestion", "Extracted static components (method variables, calls, URLs, and hardcoded C2 server IPs) are loaded into a Neo4j Malware Knowledge Graph (MKG). Method nodes map call sequences, and relationships deconstruct permission request loops."),
        ("Step 3: Multi-Agent GenAI Analysis", "Collaborative AI agents consult the Neo4j graph database to evaluate call-graphs, perform explainable code audits on suspicious blocks, fetch real-time threat intelligence (VirusTotal), and write natural language risk summaries.")
    ]
    
    for title, text in workflow_steps:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 136, 204)
        pdf.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.multi_cell(0, 5, text)
        pdf.ln(4)
        
    # ── Page 3: CONTENT CONT. ────────────────────────────────
    pdf.add_page()
    
    # 3. Key Innovation & Redundancy Alerting
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "3. Key Innovations & Multi-Channel Alerting", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(2)
    
    pdf.set_font("Helvetica", "", 10.5)
    pdf.set_text_color(26, 32, 44)
    innov_text = (
        "During live high-severity threats, delay is the enemy of containment. GAGMA implements "
        "multiple layers of notification and demo capabilities for immediate security response:"
    )
    pdf.multi_cell(0, 6, innov_text)
    pdf.ln(4)
    
    features = [
        ("Collapsible CSO Smartphone Mockup", "Displays a floating, glassmorphic phone widget on the dashboard. Upon threat identification, the phone automatically wakes up, glows green, plays a chime, and triggers an interactive simulated WhatsApp quarantine chat drawer."),
        ("Enterprise SIEM Webhooks", "Dispatches formatted JSON payloads containing full MITRE ATT&CK maps, risk scores, and decompile data straight to corporate Security Operations Centers."),
        ("Primary Alerts (WhatsApp)", "Wired via a CallMeBot API script, GAGMA streams detailed alert cards directly to security administrators' personal phones."),
        ("Backup Alerts (Telegram Bot)", "Integrates high-reliability fallback alerts via the official '@GagmaAlertsBot' to bypass WhatsApp rate-limiting or network blockades instantly.")
    ]
    
    for feat_title, feat_desc in features:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 136, 204)
        pdf.cell(0, 6, f"- {feat_title}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.set_x(15)
        pdf.multi_cell(0, 5, feat_desc)
        pdf.ln(3)
        
    pdf.ln(3)
    
    # 4. Regulatory Matrix
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(11, 25, 44)
    pdf.cell(0, 10, "4. Regulatory Compliance & Banking Standards", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(2)
    
    compliance = [
        ("RBI IT Master Direction (2023)", "Automates continuous static/dynamic risk scoring and isolates sensitive API credentials."),
        ("CERT-In SLA Guidelines", "Reduces threat disclosure time to under 60 seconds with instant multi-channel push warnings."),
        ("MITRE ATT&CK Framework", "Automatically maps method call patterns to official Mobile Threat Attack matrices."),
        ("NPCI Digital Payment Protection", "Deploys targeted heuristics to identify overlay layers aimed at UPI, GPay, and major banks.")
    ]
    
    for comp_title, comp_desc in compliance:
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(203, 97, 0) # Accent Color
        pdf.cell(0, 6, comp_title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(26, 32, 44)
        pdf.multi_cell(0, 5, comp_desc)
        pdf.ln(2)

    # Save PDF
    pdf.output("c:\\Users\\HP\\Downloads\\apps\\gagma\\gagma_project_overview.pdf")
    print("PDF Successfully generated at c:\\Users\\HP\\Downloads\\apps\\gagma\\gagma_project_overview.pdf")

if __name__ == "__main__":
    create_overview_pdf()
