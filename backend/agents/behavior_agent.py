"""
GAGMA Behavioral Analysis Agent — Detects malicious behavioral patterns
by analyzing the combination of permissions, API calls, and graph relationships.

Includes MITRE ATT&CK for Mobile mappings and banking-specific threat patterns
aligned with PSB/DFS/IBA Hackathon cybersecurity requirements.
"""
from __future__ import annotations

import logging
from models.schemas import StaticAnalysisResult, BehavioralFinding, BankingRiskFlag, KillChainStep
from services.llm_service import call_llm

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK for Mobile — Reference ────────────────
# https://attack.mitre.org/matrices/mobile/
# Tactics: TA0027 (Initial Access), TA0029 (Execution), TA0030 (Persistence),
#          TA0031 (Privilege Escalation), TA0032 (Defense Evasion),
#          TA0033 (Credential Access), TA0034 (Discovery), TA0035 (Lateral Movement),
#          TA0036 (Collection), TA0037 (Command and Control), TA0038 (Exfiltration),
#          TA0039 (Impact)

# ── Malicious Pattern Definitions ──────────────────────
MALICIOUS_PATTERNS = {
    "banking_trojan": {
        "name": "Banking Trojan Behavior",
        "description": "APK exhibits patterns consistent with banking trojans: overlay attacks, SMS interception, and credential theft targeting mobile banking applications.",
        "required_permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "required_apis": ["SmsManager", "overlay", "WebView"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0033 — Credential Access", "TA0036 — Collection"],
        "mitre_techniques": ["T1417 — Input Capture", "T1411 — User Interface Spoofing"],
    },
    "spyware": {
        "name": "Spyware / Surveillance",
        "description": "APK collects and exfiltrates personal data including contacts, call logs, SMS, and location without user consent.",
        "required_permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        ],
        "required_apis": ["ContentResolver", "TelephonyManager", "HttpURLConnection"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0036 — Collection", "TA0038 — Exfiltration"],
        "mitre_techniques": ["T1636 — Contact List", "T1430 — Location Tracking", "T1636.004 — SMS Messages"],
    },
    "ransomware": {
        "name": "Ransomware Indicators",
        "description": "APK shows encryption capabilities combined with device admin privileges, consistent with file-encrypting ransomware.",
        "required_permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ],
        "required_apis": ["Cipher", "SecretKeySpec", "crypto"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0039 — Impact", "TA0031 — Privilege Escalation"],
        "mitre_techniques": ["T1471 — Data Encrypted for Impact", "T1626 — Abuse Elevation Control Mechanism"],
    },
    "sms_fraud": {
        "name": "Premium SMS Fraud",
        "description": "APK sends SMS messages without user consent, potentially to premium-rate numbers causing financial fraud.",
        "required_permissions": [
            "android.permission.SEND_SMS",
        ],
        "required_apis": ["sendTextMessage", "SmsManager"],
        "min_match": 2,
        "severity": "high",
        "mitre_tactics": ["TA0039 — Impact"],
        "mitre_techniques": ["T1448 — Carrier Billing Fraud"],
    },
    "keylogger": {
        "name": "Keylogger / Accessibility Abuse",
        "description": "APK abuses Android Accessibility Services to monitor and record user input, capturing banking passwords and credentials.",
        "required_permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "required_apis": ["AccessibilityService", "AccessibilityEvent", "onAccessibilityEvent"],
        "min_match": 1,
        "severity": "critical",
        "mitre_tactics": ["TA0033 — Credential Access"],
        "mitre_techniques": ["T1417.001 — Keylogging", "T1417 — Input Capture"],
    },
    "dropper": {
        "name": "Malware Dropper / Loader",
        "description": "APK downloads and dynamically loads additional malicious code or applications at runtime.",
        "required_permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ],
        "required_apis": ["DexClassLoader", "PathClassLoader", "Runtime.exec"],
        "min_match": 2,
        "severity": "high",
        "mitre_tactics": ["TA0029 — Execution", "TA0027 — Initial Access"],
        "mitre_techniques": ["T1407 — Download New Code at Runtime", "T1476 — Deliver Malicious App via Authorized App Store"],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": "APK reads sensitive device data and transmits it to external servers over the network.",
        "required_permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
        ],
        "required_apis": ["HttpURLConnection", "ContentResolver", "getContentResolver"],
        "min_match": 2,
        "severity": "high",
        "mitre_tactics": ["TA0038 — Exfiltration"],
        "mitre_techniques": ["T1646 — Exfiltration Over C2 Channel", "T1636 — Protected User Data"],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation Attempt",
        "description": "APK attempts to gain elevated privileges through reflection, dynamic class loading, or exploitation techniques.",
        "required_permissions": [],
        "required_apis": ["Class.forName", "Runtime.exec", "DexClassLoader", "setAccessible"],
        "min_match": 2,
        "severity": "high",
        "mitre_tactics": ["TA0031 — Privilege Escalation", "TA0032 — Defense Evasion"],
        "mitre_techniques": ["T1404 — Exploit OS Vulnerability", "T1625 — Hijack Execution Flow"],
    },
    "persistent_threat": {
        "name": "Persistence Mechanism",
        "description": "APK ensures persistence by registering boot receivers and scheduling background tasks that survive device restarts.",
        "required_permissions": [
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "required_apis": ["AlarmManager", "JobScheduler", "BroadcastReceiver"],
        "min_match": 2,
        "severity": "medium",
        "mitre_tactics": ["TA0030 — Persistence"],
        "mitre_techniques": ["T1402 — Broadcast Receivers", "T1541 — Foreground Persistence"],
    },
    # ── NEW: Banking-Specific Patterns ──────────────────
    "upi_overlay_attack": {
        "name": "UPI / Banking Overlay Attack",
        "description": "APK requests permission to draw overlays over other applications and uses Accessibility Services — the exact mechanism used to steal UPI PINs and banking credentials by displaying fake login screens over legitimate banking apps (Drinik, AxBanker, S.O.V.A patterns).",
        "required_permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "required_apis": ["TYPE_APPLICATION_OVERLAY", "WindowManager", "AccessibilityService"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0033 — Credential Access", "TA0036 — Collection"],
        "mitre_techniques": ["T1411 — User Interface Spoofing", "T1417 — Input Capture"],
    },
    "otp_interception": {
        "name": "OTP / 2FA Interception",
        "description": "APK can read incoming SMS messages and forward them externally, enabling bypass of One-Time Password (OTP) based two-factor authentication used by all Indian banks for NEFT, IMPS, and UPI transactions.",
        "required_permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ],
        "required_apis": ["SmsMessage", "onReceive", "HttpURLConnection"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0033 — Credential Access", "TA0038 — Exfiltration"],
        "mitre_techniques": ["T1636.004 — SMS Messages", "T1449 — Exploit SS7 to Redirect Phone Calls/SMS"],
    },
    "credential_harvesting": {
        "name": "Banking Credential Harvesting",
        "description": "APK combines input method interception with network exfiltration — a sophisticated technique that captures banking usernames, passwords, and PINs as they are typed, then silently transmits them to attacker-controlled servers.",
        "required_permissions": [
            "android.permission.BIND_INPUT_METHOD",
            "android.permission.INTERNET",
        ],
        "required_apis": ["InputMethodService", "onStartInput", "HttpURLConnection"],
        "min_match": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0033 — Credential Access", "TA0038 — Exfiltration"],
        "mitre_techniques": ["T1417.001 — Keylogging", "T1646 — Exfiltration Over C2 Channel"],
    },
}

# ── Known Indian Banking App Packages ──────────────────
INDIAN_BANKING_PACKAGES = {
    "com.sbi.SBIFreedomPlus",
    "com.sbi.lotusintouch",
    "com.sbi.SBI_Associate_Yono",
    "com.sbi.yono",
    "com.sbi.yonolite",
    "net.one97.paytm",
    "com.phonepe.app",
    "com.google.android.apps.nbu.paisa.user",
    "com.hdfc.ergo",
    "com.msf.kony.hdfcbank",
    "com.htc.icicibank",
    "com.icicibank.pockets",
    "com.snapwork.hdfc",
    "com.axis.mobile",
    "com.kotak.mobilebanking",
    "com.pnb.mbanking",
    "com.csam.icici.bank.imobile",
    "com.union.CUB",
    "com.bob.mobile",
    "com.boi.mobilebanking",
    "com.canara.mobilebanking",
    "com.indusind.mobile.banking",
    "com.yesbank.yesmobile",
    "com.mgs.android.idbigobank",
    "com.tatacommunications.nativepayment",
    "com.mobikwik_new",
    "com.freecharge.android",
    "in.amazon.mShop.android.shopping",
}

# Partial name matches for impersonation detection
BANKING_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "boi", "canara",
    "paytm", "phonepe", "gpay", "bhim", "upi", "neft", "imps",
    "bankofbaroda", "unionbank", "yesbank", "indusind", "idbi", "federal",
]


def analyze_behavior(result: StaticAnalysisResult) -> list[BehavioralFinding]:
    """
    Analyze APK for known malicious behavioral patterns by correlating
    permissions, API calls, and components. Returns findings with
    MITRE ATT&CK mappings.
    """
    findings: list[BehavioralFinding] = []

    # Collect all permission names and API names for matching
    perm_names = {p.name for p in result.permissions}
    api_names = {a.api_call for a in result.suspicious_api_calls}
    api_categories = {a.category for a in result.suspicious_api_calls}

    for pattern_key, pattern in MALICIOUS_PATTERNS.items():
        evidence = []
        match_score = 0

        # Check permissions
        matched_perms = perm_names.intersection(set(pattern["required_permissions"]))
        if matched_perms:
            match_score += len(matched_perms)
            evidence.extend([f"Permission: {p.split('.')[-1]}" for p in matched_perms])

        # Check API calls
        for api_pattern in pattern["required_apis"]:
            for api_name in api_names:
                if api_pattern.lower() in api_name.lower():
                    match_score += 1
                    evidence.append(f"API: {api_name}")
                    break
            else:
                # Also check categories
                if api_pattern.lower() in api_categories:
                    match_score += 1
                    evidence.append(f"Category: {api_pattern}")

        # Check if we meet minimum match threshold
        if match_score >= pattern["min_match"]:
            findings.append(BehavioralFinding(
                pattern_name=pattern["name"],
                severity=pattern["severity"],
                description=pattern["description"],
                evidence=evidence,
                graph_paths=[
                    f"(:APK)-[:REQUESTS_PERMISSION]->(:Permission {{{p}}})"
                    for p in list(matched_perms)[:3]
                ],
                mitre_tactics=pattern.get("mitre_tactics", []),
                mitre_techniques=pattern.get("mitre_techniques", []),
            ))

    return findings


def analyze_banking_flags(result: StaticAnalysisResult) -> tuple[list[BankingRiskFlag], list[KillChainStep]]:
    """
    Perform banking-sector specific risk assessment.
    Returns banking flags and reconstructed attack kill chain.
    """
    flags: list[BankingRiskFlag] = []
    perm_names = {p.name for p in result.permissions}
    api_names = {a.api_call for a in result.suspicious_api_calls}
    pkg = result.metadata.package_name.lower()

    # ── Check 1: Banking App Impersonation ──────────────
    is_known_package = result.metadata.package_name in INDIAN_BANKING_PACKAGES
    looks_like_bank = any(kw in pkg for kw in BANKING_KEYWORDS)

    if looks_like_bank and not is_known_package:
        flags.append(BankingRiskFlag(
            flag_type="APP_IMPERSONATION",
            title="Suspected Banking App Impersonation",
            detail=f"Package name '{result.metadata.package_name}' contains banking keywords but does not match any verified Indian banking application. This is consistent with phishing APKs designed to deceive users.",
            severity="critical",
            affected_apps=["SBI YONO", "HDFC MobileBanking", "ICICI iMobile", "Axis Mobile"],
        ))

    # ── Check 2: UPI Overlay Capability ─────────────────
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perm_names
    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_names
    if has_overlay and has_accessibility:
        flags.append(BankingRiskFlag(
            flag_type="UPI_OVERLAY",
            title="UPI PIN Overlay Attack Capability",
            detail="APK can render transparent windows over any application including banking apps. Combined with Accessibility Services, it can display fake UPI PIN entry screens that harvest credentials while the victim believes they are using a legitimate banking interface.",
            severity="critical",
            affected_apps=["PhonePe", "Google Pay", "Paytm", "BHIM UPI", "Bank UPI Apps"],
        ))

    # ── Check 3: OTP Interception ────────────────────────
    has_read_sms = "android.permission.READ_SMS" in perm_names
    has_receive_sms = "android.permission.RECEIVE_SMS" in perm_names
    has_internet = "android.permission.INTERNET" in perm_names
    if (has_read_sms or has_receive_sms) and has_internet:
        flags.append(BankingRiskFlag(
            flag_type="OTP_INTERCEPTION",
            title="Banking OTP Interception Risk",
            detail="APK can intercept incoming SMS messages and forward them over the internet. This directly enables bypass of OTP-based two-factor authentication for NEFT, IMPS, RTGS, and UPI transactions, allowing unauthorized fund transfers from victim accounts.",
            severity="critical",
            affected_apps=["All Indian Banks (OTP-based 2FA)", "UPI Apps", "Net Banking Portals"],
        ))

    # ── Check 4: Device Admin Lock (Ransomware) ──────────
    has_device_admin = "android.permission.BIND_DEVICE_ADMIN" in perm_names
    has_crypto = any("cipher" in a.lower() or "secretkey" in a.lower() for a in api_names)
    if has_device_admin and has_crypto:
        flags.append(BankingRiskFlag(
            flag_type="DEVICE_LOCKOUT",
            title="Device Lockout / Ransomware Capability",
            detail="APK requests Device Administrator privileges and contains cryptographic APIs. This combination enables full device lockout and file encryption — ransomware tactics increasingly used to coerce victims into making banking transfers.",
            severity="critical",
            affected_apps=["All device data and applications"],
        ))

    # ── Check 5: Silent SMS Premium Fraud ───────────────
    has_send_sms = "android.permission.SEND_SMS" in perm_names
    has_sms_api = any("smsmanager" in a.lower() or "sendtextmessage" in a.lower() for a in api_names)
    if has_send_sms and has_sms_api:
        flags.append(BankingRiskFlag(
            flag_type="PREMIUM_SMS_FRAUD",
            title="Premium SMS Financial Fraud",
            detail="APK can send SMS messages without user interaction. This enables subscription fraud and unauthorized charges to the victim's mobile account, which in India is directly linked to wallet and UPI services.",
            severity="high",
            affected_apps=["Mobile Wallets", "Carrier Billing", "UPI via SMS"],
        ))

    # ── Build Attack Kill Chain ──────────────────────────
    kill_chain = _build_kill_chain(result, flags)

    return flags, kill_chain


def _build_kill_chain(result: StaticAnalysisResult, flags: list[BankingRiskFlag]) -> list[KillChainStep]:
    """Reconstruct the likely attack kill chain based on capabilities."""
    perm_names = {p.name for p in result.permissions}
    steps: list[KillChainStep] = []

    # Stage 1: Always present — Initial Access
    steps.append(KillChainStep(
        stage=1,
        name="Social Engineering",
        description="Victim is deceived into installing APK via phishing SMS, WhatsApp link, or fake app store listing mimicking a banking application.",
        technique="T1476",
    ))

    # Stage 2: Persistence
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_names:
        steps.append(KillChainStep(
            stage=2,
            name="Persistence",
            description="Registers a BOOT_COMPLETED receiver to auto-start on device restart, ensuring the malware survives reboot cycles.",
            technique="T1402",
        ))

    # Stage 3: Privilege
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_names:
        steps.append(KillChainStep(
            stage=3,
            name="Privilege Acquisition",
            description="Prompts user to grant Accessibility Service permission under the guise of a 'performance' or 'accessibility' feature, gaining control of the UI.",
            technique="T1626",
        ))

    # Stage 4: Overlay / Credential Theft
    flag_types = {f.flag_type for f in flags}
    if "UPI_OVERLAY" in flag_types:
        steps.append(KillChainStep(
            stage=4,
            name="UI Overlay Attack",
            description="Waits for victim to open a banking or UPI app, then immediately renders a transparent overlay capturing PIN entry and credentials.",
            technique="T1411",
        ))
    elif "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_names:
        steps.append(KillChainStep(
            stage=4,
            name="Keylogging",
            description="Monitors Accessibility Events to capture all text input, including banking passwords, PINs, and transaction details.",
            technique="T1417.001",
        ))

    # Stage 5: OTP Intercept
    if "OTP_INTERCEPTION" in flag_types:
        steps.append(KillChainStep(
            stage=5,
            name="OTP Interception",
            description="Silently intercepts incoming OTP SMS from bank, forwarding to attacker's server before the victim can see it, bypassing 2FA.",
            technique="T1636.004",
        ))

    # Stage 6: Exfiltration
    if "android.permission.INTERNET" in perm_names:
        steps.append(KillChainStep(
            stage=6,
            name="Data Exfiltration",
            description="Collected credentials, OTPs, contacts, and device information are transmitted to attacker-controlled C2 servers over encrypted HTTPS connections.",
            technique="T1646",
        ))

    # Stage 7: Financial Fraud (if applicable)
    if "PREMIUM_SMS_FRAUD" in flag_types or "OTP_INTERCEPTION" in flag_types:
        steps.append(KillChainStep(
            stage=7,
            name="Financial Fraud",
            description="Attacker uses harvested credentials and intercepted OTPs to initiate unauthorized NEFT/IMPS/UPI transfers from victim's bank account.",
            technique="T1448",
        ))

    return steps


def get_ai_behavioral_analysis(
    result: StaticAnalysisResult,
    findings: list[BehavioralFinding],
) -> str:
    """
    Use LLM to provide deeper behavioral analysis and threat assessment.
    """
    permissions_str = ", ".join(
        p.name.split(".")[-1] for p in result.permissions if p.is_suspicious
    )
    apis_str = ", ".join(
        f"{a.api_call} ({a.category})" for a in result.suspicious_api_calls[:15]
    )
    findings_str = "\n".join(
        f"- {f.pattern_name} [{f.severity.upper()}]: {f.description}"
        for f in findings
    )

    system_prompt = """You are a senior cybersecurity analyst at a banking CERT (Computer Emergency Response Team).
Analyze this Android APK submission and provide a concise technical threat assessment.
Be specific, technical, and direct. Reference banking fraud context where relevant."""

    user_prompt = f"""Analyze this Android APK for malicious behavior targeting banking users:

PACKAGE: {result.metadata.package_name}
DANGEROUS PERMISSIONS: {permissions_str or "None detected"}
SUSPICIOUS APIs: {apis_str or "None detected"}
DETECTED PATTERNS: {findings_str or "None detected"}

Provide a security assessment under 150 words covering:
1. **Threat Classification**: What malware type is this?
2. **Banking Impact**: What specific banking/financial risk does this pose?
3. **Immediate Action**: What should the incident response team do?

Be technical and direct."""

    return call_llm(system_prompt, user_prompt, temperature=0.3)
