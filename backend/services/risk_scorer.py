"""
GAGMA Risk Scorer — Computes a comprehensive risk score
based on permissions, API calls, behavioral patterns, and threat intel.
"""
from __future__ import annotations

from models.schemas import (
    StaticAnalysisResult,
    BehavioralFinding,
    RiskScoreBreakdown,
    RiskLevel,
)


def calculate_risk_score(
    result: StaticAnalysisResult,
    findings: list[BehavioralFinding],
    threat_intel: dict | None = None,
) -> RiskScoreBreakdown:
    """
    Calculate a weighted risk score (0-100) from all analysis data.

    Breakdown:
    - Permissions: 0-25 points
    - API Calls: 0-25 points
    - Behavioral Patterns: 0-30 points
    - Threat Intelligence: 0-20 points
    """

    # ── Permissions Score (0-25) ────────────────────────
    dangerous_perms = sum(1 for p in result.permissions if p.is_suspicious)
    perm_score = min(25, dangerous_perms * 3)

    # Extra weight for particularly dangerous combos
    perm_names = {p.name for p in result.permissions}
    high_risk_perms = {
        "android.permission.SEND_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }
    critical_perm_count = len(perm_names.intersection(high_risk_perms))
    perm_score = min(25, perm_score + critical_perm_count * 4)

    # ── API Calls Score (0-25) ─────────────────────────
    severity_weights = {"critical": 5, "high": 3, "medium": 1.5, "low": 0.5}
    api_score = 0
    for api_call in result.suspicious_api_calls:
        api_score += severity_weights.get(api_call.severity, 1)
    api_score = min(25, api_score)

    # ── Behavioral Pattern Score (0-30) ────────────────
    severity_finding_weights = {"critical": 12, "high": 8, "medium": 4, "low": 2}
    behavior_score = 0
    for finding in findings:
        behavior_score += severity_finding_weights.get(finding.severity, 2)
    behavior_score = min(30, behavior_score)

    # ── Threat Intelligence Score (0-20) ───────────────
    intel_score = 0
    if threat_intel:
        vt = threat_intel.get("virustotal")
        if vt and vt.get("found"):
            malicious = vt.get("malicious", 0)
            total = vt.get("total_engines", 1)
            if malicious > 0:
                intel_score = min(20, int((malicious / max(total, 1)) * 20))

        # IP reputation
        for ip_rep in threat_intel.get("ip_reputations", []):
            if ip_rep.get("abuse_confidence_score", 0) > 50:
                intel_score = min(20, intel_score + 5)

    # ── Total ──────────────────────────────────────────
    total = perm_score + api_score + behavior_score + intel_score
    total = min(100, max(0, total))

    # Determine risk level
    if total >= 75:
        risk_level = RiskLevel.CRITICAL
    elif total >= 50:
        risk_level = RiskLevel.HIGH
    elif total >= 25:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return RiskScoreBreakdown(
        permissions_score=round(perm_score, 1),
        api_calls_score=round(api_score, 1),
        behavioral_score=round(behavior_score, 1),
        threat_intel_score=round(intel_score, 1),
        total_score=round(total, 1),
        risk_level=risk_level,
    )
