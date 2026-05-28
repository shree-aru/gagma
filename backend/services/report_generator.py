"""
GAGMA Report Generator — CERT-In / RBI Compliant Incident Report.
Produces detailed analysis reports aligned with PSB/DFS/IBA cybersecurity standards.
"""
from __future__ import annotations

from datetime import datetime, timezone
from models.schemas import (
    StaticAnalysisResult,
    BehavioralFinding,
    RiskScoreBreakdown,
    BankingRiskFlag,
    KillChainStep,
)


def generate_report(
    analysis_id: str,
    result: StaticAnalysisResult,
    risk_score: RiskScoreBreakdown,
    findings: list[BehavioralFinding],
    ai_summary: str = "",
    threat_intel: dict | None = None,
    banking_flags: list[BankingRiskFlag] | None = None,
    kill_chain: list[KillChainStep] | None = None,
) -> str:
    """Generate a CERT-In compliant Markdown analysis report."""
    meta = result.metadata
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    banking_flags = banking_flags or []
    kill_chain = kill_chain or []

    risk_labels = {
        "LOW": "LOW RISK",
        "MEDIUM": "MEDIUM RISK",
        "HIGH": "HIGH RISK",
        "CRITICAL": "CRITICAL RISK",
    }

    sla_map = {
        "CRITICAL": "Immediate (within 1 hour) — Notify CISO, isolate affected devices, file CERT-In report",
        "HIGH": "Within 4 hours — Escalate to security team, begin containment",
        "MEDIUM": "Within 24 hours — Security review required before any deployment",
        "LOW": "Routine — Document and monitor",
    }

    report = f"""# GAGMA Mobile Threat Analysis Report
## Incident Reference: GAGMA-{analysis_id.upper()}

**Classification:** {risk_labels.get(risk_score.risk_level.value, risk_score.risk_level.value)}
**Analysis ID:** `{analysis_id}`
**Generated:** {timestamp}
**Risk Score:** {risk_score.total_score}/100
**Regulatory Framework:** RBI Cybersecurity Framework (2023) | CERT-In Guidelines | PSB Security Policy

---

## Executive Summary

{ai_summary or "_AI threat assessment unavailable. Configure GEMINI_API_KEY for automated analysis._"}

---

## 1. APK Identification

| Property | Value |
|----------|-------|
| Package Name | `{meta.package_name}` |
| Version | {meta.version_name} (Build: {meta.version_code}) |
| Minimum SDK | Android API {meta.min_sdk} |
| Target SDK | Android API {meta.target_sdk} |
| Main Activity | `{meta.main_activity}` |
| File Size | {_format_size(meta.file_size)} |
| MD5 Hash | `{meta.md5}` |
| SHA-256 Hash | `{meta.sha256}` |

---

## 2. Risk Score Breakdown

| Category | Score | Maximum | Weight |
|----------|-------|---------|--------|
| Permission Analysis | {risk_score.permissions_score} | 25 | 25% |
| Suspicious API Calls | {risk_score.api_calls_score} | 25 | 25% |
| Behavioral Patterns | {risk_score.behavioral_score} | 30 | 30% |
| Threat Intelligence | {risk_score.threat_intel_score} | 20 | 20% |
| **Total Risk Score** | **{risk_score.total_score}** | **100** | — |

**Risk Classification:** {risk_score.risk_level.value}
**Response SLA:** {sla_map.get(risk_score.risk_level.value, "Standard review")}

---
"""

    # ── Section 3: Banking Risk Flags ─────────────────────
    if banking_flags:
        report += "## 3. Banking Sector Risk Assessment\n\n"
        report += "_The following risks are specific to the Indian banking and payments ecosystem:_\n\n"
        for flag in banking_flags:
            sev = flag.severity.upper()
            report += f"### [{sev}] {flag.title}\n\n"
            report += f"{flag.detail}\n\n"
            if flag.affected_apps:
                report += f"**Targeted Applications:** {', '.join(flag.affected_apps)}\n\n"
        report += "---\n\n"
    else:
        report += "## 3. Banking Sector Risk Assessment\n\n"
        report += "_No banking-specific attack patterns detected._\n\n---\n\n"

    # ── Section 4: Attack Kill Chain ──────────────────────
    if kill_chain:
        report += "## 4. Attack Kill Chain\n\n"
        report += "Reconstructed attack sequence based on static capability analysis:\n\n"
        for step in kill_chain:
            report += f"**Stage {step.stage} — {step.name}** _(MITRE: {step.technique})_\n\n"
            report += f"{step.description}\n\n"
        report += "---\n\n"
    else:
        report += "## 4. Attack Kill Chain\n\n_Insufficient data to reconstruct kill chain._\n\n---\n\n"

    # ── Section 5: Behavioral Analysis ───────────────────
    report += "## 5. Behavioral Analysis\n\n"
    if findings:
        for f in findings:
            sev = f.severity.upper()
            report += f"### [{sev}] {f.pattern_name}\n\n"
            report += f"{f.description}\n\n"

            if f.mitre_techniques:
                report += f"**MITRE ATT&CK:** {' | '.join(f.mitre_techniques)}\n\n"
            if f.mitre_tactics:
                report += f"**Tactics:** {' | '.join(f.mitre_tactics)}\n\n"
            if f.evidence:
                report += "**Evidence:**\n"
                for e in f.evidence:
                    report += f"- `{e}`\n"
                report += "\n"
    else:
        report += "_No known malicious behavioral patterns detected._\n\n"
    report += "---\n\n"

    # ── Section 6: Permissions Analysis ──────────────────
    dangerous = [p for p in result.permissions if p.is_suspicious]
    normal = [p for p in result.permissions if not p.is_suspicious]
    report += "## 6. Permissions Analysis\n\n"

    if dangerous:
        report += f"### Dangerous Permissions ({len(dangerous)} found)\n\n"
        report += "| Permission | Risk |\n|------------|------|\n"
        for p in dangerous:
            short = p.name.split(".")[-1]
            report += f"| `{short}` | {p.description or 'High — Direct privacy/security impact'} |\n"
        report += "\n"

    if normal:
        report += f"### Standard Permissions ({len(normal)} total)\n\n"
        report += ", ".join(f"`{p.name.split('.')[-1]}`" for p in normal[:12])
        if len(normal) > 12:
            report += f" ... and {len(normal) - 12} more"
        report += "\n\n"
    report += "---\n\n"

    # ── Section 7: Indicators of Compromise ──────────────
    report += "## 7. Indicators of Compromise (IoCs)\n\n"

    report += f"**APK Hash (SHA-256):** `{meta.sha256}`\n\n"
    report += f"**Package Identifier:** `{meta.package_name}`\n\n"

    if result.suspicious_api_calls:
        report += "### Suspicious API Calls\n\n"
        report += "| API | Category | Severity |\n|-----|----------|----------|\n"
        for api in result.suspicious_api_calls[:20]:
            report += f"| `{api.api_call[:60]}` | {api.category} | {api.severity.upper()} |\n"
        report += "\n"

    if result.extracted_urls:
        report += "### Network Indicators — URLs\n\n"
        for url in result.extracted_urls[:15]:
            report += f"- `{url}`\n"
        report += "\n"

    if result.extracted_ips:
        report += "### Network Indicators — IP Addresses\n\n"
        for ip in result.extracted_ips[:15]:
            report += f"- `{ip}`\n"
        report += "\n"

    if not result.suspicious_api_calls and not result.extracted_urls and not result.extracted_ips:
        report += "_No network-based IoCs identified._\n\n"
    report += "---\n\n"

    # ── Section 8: Threat Intelligence ───────────────────
    report += "## 8. Threat Intelligence\n\n"
    if threat_intel:
        vt = threat_intel.get("virustotal")
        if vt and vt.get("found"):
            report += "### VirusTotal Analysis\n\n"
            report += f"| Metric | Value |\n|--------|-------|\n"
            report += f"| Detection Rate | {vt.get('detection_rate', 'N/A')} |\n"
            report += f"| Malicious Engines | {vt.get('malicious', 0)} |\n"
            report += f"| Threat Family | {vt.get('popular_threat_name', 'Unknown')} |\n"
            report += f"| Tags | {', '.join(vt.get('tags', []))} |\n"
            report += f"| VT Link | [{vt.get('link', '')}]({vt.get('link', '')}) |\n\n"
        elif vt:
            report += "### VirusTotal: Sample not found in database (new/private sample)\n\n"

        ip_reps = threat_intel.get("ip_reputations", [])
        if ip_reps:
            report += "### IP Reputation Analysis\n\n"
            report += "| IP Address | Abuse Score | Country | ISP |\n|------------|-------------|---------|-----|\n"
            for ip_rep in ip_reps:
                report += f"| `{ip_rep['ip']}` | {ip_rep.get('abuse_confidence_score', 0)}% | {ip_rep.get('country', 'Unknown')} | {ip_rep.get('isp', 'Unknown')} |\n"
            report += "\n"
    else:
        report += "_Threat intelligence not available. Configure VIRUSTOTAL_API_KEY._\n\n"
    report += "---\n\n"

    # ── Section 9: Component Summary ─────────────────────
    report += "## 9. Application Component Analysis\n\n"
    report += f"| Component | Count | Risk Indicator |\n|-----------|-------|----------------|\n"
    report += f"| Activities | {len(result.activities)} | {_risk_indicator(len(result.activities), 5, 15)} |\n"
    report += f"| Services | {len(result.services)} | {_risk_indicator(len(result.services), 2, 8)} |\n"
    report += f"| Broadcast Receivers | {len(result.receivers)} | {_risk_indicator(len(result.receivers), 3, 10)} |\n"
    report += f"| Content Providers | {len(result.providers)} | {_risk_indicator(len(result.providers), 1, 5)} |\n"
    report += f"| Total Classes | {result.classes_count} | {_risk_indicator(result.classes_count, 200, 2000)} |\n"
    report += f"| Total Methods | {result.methods_count} | — |\n\n"
    report += "---\n\n"

    # ── Section 10: Recommendations ──────────────────────
    report += "## 10. Incident Response Recommendations\n\n"

    if risk_score.total_score >= 75:
        report += """### Immediate Actions Required

1. **Containment**: Block this APK's SHA-256 hash across all managed devices via MDM policy immediately.
2. **Notification**: Alert the Information Security team and CISO. Initiate incident response protocol.
3. **User Impact Assessment**: Query device management logs to identify if any users have installed this APK.
4. **Account Security**: Force password reset and OTP re-registration for any users on affected devices.
5. **CERT-In Notification**: File incident report with CERT-In within 6 hours per RBI Circular RBI/2021-22/101.
6. **Evidence Preservation**: Capture device forensic image before any remediation for legal proceedings.

### Regulatory Obligations

Per **RBI Master Direction on IT (2021)**, this incident may require:
- Mandatory reporting if customer data is compromised
- Board-level communication if financial fraud is suspected
- Coordination with NPCI if UPI transactions are affected

"""
    elif risk_score.total_score >= 50:
        report += """### High Priority Actions

1. Block APK distribution across all managed channels.
2. Conduct dynamic analysis in a sandboxed environment.
3. Monitor network traffic for C2 communication patterns.
4. Cross-reference APK hash with threat intelligence platforms.
5. Notify security team for further investigation.

"""
    elif risk_score.total_score >= 25:
        report += """### Standard Review Actions

1. Review flagged permissions and API calls in detail.
2. Conduct code review of highlighted sections.
3. Test in isolated environment before any production deployment.
4. Document findings and schedule follow-up scan.

"""
    else:
        report += """### Routine Actions

1. APK shows no significant malicious indicators.
2. Standard security review practices apply.
3. Continue periodic monitoring with automated scanning.

"""

    report += "---\n\n"
    report += f"*Report generated by GAGMA — Graph-Augmented GenAI Malware Analyst | PSB Cybersecurity Hackathon 2026*\n"
    report += f"*Aligned with: CERT-In Guidelines | RBI Cybersecurity Framework | MITRE ATT&CK for Mobile*\n"

    return report


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _risk_indicator(value: int, medium_threshold: int, high_threshold: int) -> str:
    """Return a risk indicator string based on thresholds."""
    if value >= high_threshold:
        return "Elevated"
    elif value >= medium_threshold:
        return "Moderate"
    return "Normal"
