"""
GAGMA Dynamic Analysis Simulator — Behavioral sandbox emulation.

Since true dynamic analysis requires an Android emulator (which needs Android SDK
and significant compute), this module performs "emulated dynamic analysis" by:

1. Inferring runtime behavior from static capabilities (permissions + APIs)
2. Simulating network communication patterns from extracted URLs/IPs
3. Predicting data exfiltration flows based on permission combinations
4. Generating a dynamic analysis report section

This approach is standard in enterprise security products where full sandbox
execution isn't always feasible (e.g., CrowdStrike Falcon, SentinelOne).

For the hackathon: demonstrates the concept and analytical capability.
For production (AWS): would integrate with Android emulator farm via AWS Device Farm.
"""
from __future__ import annotations

import logging
from models.schemas import StaticAnalysisResult

logger = logging.getLogger(__name__)


class DynamicFinding:
    """A finding from emulated dynamic analysis."""
    def __init__(self, category: str, severity: str, title: str, detail: str,
                 network_indicator: str = "", data_flow: str = ""):
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.network_indicator = network_indicator
        self.data_flow = data_flow

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "network_indicator": self.network_indicator,
            "data_flow": self.data_flow,
        }


def emulate_dynamic_analysis(result: StaticAnalysisResult) -> dict:
    """
    Perform emulated dynamic analysis based on static capabilities.
    
    Returns a dict with:
    - runtime_behaviors: predicted runtime actions
    - network_activity: predicted network communications
    - data_flows: predicted data exfiltration paths
    - sandbox_verdict: overall dynamic verdict
    """
    findings: list[DynamicFinding] = []
    perm_names = {p.name for p in result.permissions}
    api_names = {a.api_call for a in result.suspicious_api_calls}

    # ── Runtime Behavior Prediction ────────────────────
    
    # Boot persistence
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_names:
        findings.append(DynamicFinding(
            category="persistence",
            severity="high",
            title="Auto-Start on Boot",
            detail="Application registers BOOT_COMPLETED receiver. Will automatically "
                   "execute background services immediately after device restart without "
                   "user interaction.",
            data_flow="BOOT_COMPLETED → BroadcastReceiver → Background Service",
        ))

    # Overlay rendering
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perm_names
    has_overlay_api = any("overlay" in a.lower() or "windowmanager" in a.lower() for a in api_names)
    if has_overlay and has_overlay_api:
        findings.append(DynamicFinding(
            category="ui_manipulation",
            severity="critical",
            title="UI Overlay Injection at Runtime",
            detail="Application will draw transparent windows over banking apps at runtime. "
                   "When victim opens a UPI/banking app, the malware renders a fake login "
                   "screen within milliseconds, capturing credentials before the real app loads.",
            data_flow="PackageManager.onAppLaunch → WindowManager.addView → Fake UI → credential capture",
        ))

    # SMS interception at runtime
    has_sms_read = "android.permission.RECEIVE_SMS" in perm_names
    has_sms_api = any("sms" in a.lower() for a in api_names)
    if has_sms_read and has_sms_api:
        findings.append(DynamicFinding(
            category="data_interception",
            severity="critical",
            title="SMS Broadcast Interception",
            detail="Application registers a high-priority SMS BroadcastReceiver that intercepts "
                   "incoming messages BEFORE the default SMS app. Banking OTPs are captured "
                   "and silently forwarded to attacker's C2 server, then optionally deleted "
                   "to prevent the victim from seeing them.",
            data_flow="SMS_RECEIVED → BroadcastReceiver (priority=999) → HTTP POST to C2",
        ))

    # Accessibility abuse
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_names:
        findings.append(DynamicFinding(
            category="input_capture",
            severity="critical",
            title="Accessibility Event Monitoring",
            detail="Application monitors all AccessibilityEvents system-wide at runtime. "
                   "Every text input, button press, and screen change across ALL applications "
                   "is captured — including banking passwords, UPI PINs, and MPIN entries.",
            data_flow="AccessibilityService → onAccessibilityEvent → keylog buffer → exfiltrate",
        ))

    # ── Network Activity Prediction ────────────────────
    
    # C2 communication
    suspicious_urls = [u for u in result.extracted_urls
                       if "telegram" in u.lower() or "pastebin" in u.lower()
                       or not any(safe in u.lower() for safe in ["google", "android", "microsoft", "apple", "github"])]
    
    if suspicious_urls:
        findings.append(DynamicFinding(
            category="network",
            severity="high",
            title="Command & Control Communication",
            detail=f"Application will establish connections to {len(suspicious_urls)} "
                   f"suspicious external endpoints at runtime. These include non-standard "
                   f"domains likely used for credential exfiltration and receiving attacker commands.",
            network_indicator=", ".join(suspicious_urls[:5]),
            data_flow="Stolen data → HTTP/HTTPS POST → C2 server",
        ))

    # Telegram bot exfiltration (common in Indian banking trojans)
    telegram_urls = [u for u in result.extracted_urls if "telegram" in u.lower()]
    if telegram_urls:
        findings.append(DynamicFinding(
            category="exfiltration",
            severity="critical",
            title="Telegram Bot Data Exfiltration",
            detail="Application uses Telegram Bot API to exfiltrate stolen data. This is a "
                   "common technique in Indian banking trojans (Drinik, EventBot) because "
                   "Telegram channels are difficult to take down and provide real-time "
                   "notification to attackers when credentials are captured.",
            network_indicator=telegram_urls[0],
            data_flow="Captured OTP/credentials → JSON payload → Telegram Bot API → Attacker channel",
        ))

    # ── Data Flow Analysis ─────────────────────────────
    
    # Contact/SMS exfiltration
    reads_contacts = "android.permission.READ_CONTACTS" in perm_names
    has_internet = "android.permission.INTERNET" in perm_names
    if reads_contacts and has_internet:
        findings.append(DynamicFinding(
            category="data_exfiltration",
            severity="high",
            title="Contact List Exfiltration",
            detail="Application reads the device contact list and transmits it over the network. "
                   "Contacts are used by attackers for targeted phishing campaigns — sending "
                   "malicious APK links to the victim's contacts from trusted phone numbers.",
            data_flow="ContentResolver(ContactsContract) → JSON serialize → HTTP POST",
        ))

    # Device fingerprinting
    has_device_info = any("telephonymanager" in a.lower() or "getdeviceid" in a.lower() for a in api_names)
    if has_device_info:
        findings.append(DynamicFinding(
            category="reconnaissance",
            severity="medium",
            title="Device Fingerprinting",
            detail="Application collects unique device identifiers (IMEI, IMSI, SIM serial) "
                   "at runtime. This fingerprint is used to track victims across reinstalls "
                   "and to associate stolen credentials with specific devices for targeted fraud.",
            data_flow="TelephonyManager → getDeviceId/getSubscriberId → C2 registration",
        ))

    # ── Sandbox Verdict ────────────────────────────────
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    
    if critical_count >= 2:
        verdict = "MALICIOUS"
        verdict_detail = (f"Dynamic emulation identified {critical_count} critical and "
                         f"{high_count} high-severity runtime behaviors. This application "
                         f"will actively steal banking credentials and intercept OTPs at runtime.")
    elif critical_count >= 1 or high_count >= 2:
        verdict = "SUSPICIOUS"
        verdict_detail = (f"Dynamic emulation identified concerning runtime behaviors. "
                         f"Full sandbox execution recommended before deployment.")
    else:
        verdict = "CLEAN"
        verdict_detail = "No significant malicious runtime behaviors predicted."

    return {
        "runtime_behaviors": [f.to_dict() for f in findings],
        "total_findings": len(findings),
        "critical_findings": critical_count,
        "sandbox_verdict": verdict,
        "verdict_detail": verdict_detail,
        "analysis_method": "Static-to-Dynamic inference engine (production: AWS Device Farm sandbox)",
    }
