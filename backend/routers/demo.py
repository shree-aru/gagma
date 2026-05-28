"""
GAGMA Demo Router — Pre-built threat profiles for hackathon demonstrations.

Provides /api/demo/{scenario} endpoints that inject synthetic analysis results
matching real-world Indian banking trojans, enabling live demos without
requiring actual malware samples.
"""
from __future__ import annotations

import uuid
import logging
from fastapi import APIRouter

from models.schemas import (
    AnalysisResponse, AnalysisStatus, StaticAnalysisResult,
    APKMetadata, PermissionInfo, SuspiciousAPICall,
    BehavioralFinding, BankingRiskFlag, KillChainStep,
)
from agents.behavior_agent import analyze_behavior, analyze_banking_flags, get_ai_behavioral_analysis
from services.risk_scorer import calculate_risk_score
from services.report_generator import generate_report
from services.dynamic_analyzer import emulate_dynamic_analysis
from routers.analysis import analyses, reports

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/demo", tags=["demo"])


# ── Drinik v3 Banking Trojan ───────────────────────────
def _drinik_profile() -> StaticAnalysisResult:
    """Simulate Drinik v3 — UPI overlay + OTP interception trojan targeting Indian banks."""
    return StaticAnalysisResult(
        metadata=APKMetadata(
            package_name="com.tax.filing.india.returns2024",
            version_name="3.1.7", version_code="18",
            min_sdk=21, target_sdk=31,
            main_activity="com.tax.filing.india.SplashActivity",
            md5="a1b2c3d4e5f60011223344556677aabb",
            sha256="d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
            file_size=4_200_000,
        ),
        permissions=[
            PermissionInfo(name="android.permission.INTERNET", is_suspicious=False),
            PermissionInfo(name="android.permission.ACCESS_NETWORK_STATE", is_suspicious=False),
            PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW", protection_level="dangerous", is_suspicious=True, description="Can draw overlays on top of other apps"),
            PermissionInfo(name="android.permission.BIND_ACCESSIBILITY_SERVICE", protection_level="signature", is_suspicious=True, description="Can monitor and control UI (keylogging risk)"),
            PermissionInfo(name="android.permission.RECEIVE_SMS", protection_level="dangerous", is_suspicious=True, description="Can intercept incoming SMS (OTP theft)"),
            PermissionInfo(name="android.permission.READ_SMS", protection_level="dangerous", is_suspicious=True, description="Can read all SMS messages"),
            PermissionInfo(name="android.permission.SEND_SMS", protection_level="dangerous", is_suspicious=True, description="Can send SMS messages (potential premium SMS fraud)"),
            PermissionInfo(name="android.permission.READ_CONTACTS", protection_level="dangerous", is_suspicious=True, description="Can read all contacts"),
            PermissionInfo(name="android.permission.READ_PHONE_STATE", protection_level="dangerous", is_suspicious=True, description="Can read phone state and identity"),
            PermissionInfo(name="android.permission.RECEIVE_BOOT_COMPLETED", protection_level="dangerous", is_suspicious=True, description="Starts automatically on device boot"),
            PermissionInfo(name="android.permission.CAMERA", protection_level="dangerous", is_suspicious=True, description="Can access device camera"),
            PermissionInfo(name="android.permission.WRITE_EXTERNAL_STORAGE", protection_level="dangerous", is_suspicious=True, description="Can write to device storage"),
            PermissionInfo(name="android.permission.REQUEST_INSTALL_PACKAGES", protection_level="dangerous", is_suspicious=True, description="Can install other APKs"),
        ],
        suspicious_api_calls=[
            SuspiciousAPICall(method="(static)", api_call="TYPE_APPLICATION_OVERLAY", category="overlay", severity="critical"),
            SuspiciousAPICall(method="(static)", api_call="WindowManager.LayoutParams", category="overlay", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="AccessibilityService", category="accessibility", severity="critical"),
            SuspiciousAPICall(method="(static)", api_call="onAccessibilityEvent", category="accessibility", severity="critical"),
            SuspiciousAPICall(method="(static)", api_call="SmsMessage.createFromPdu", category="sms", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="SmsManager", category="sms", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="sendTextMessage", category="sms", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="HttpURLConnection", category="network", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="WebView.loadUrl", category="network", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="ContentResolver", category="data_access", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="TelephonyManager", category="device_info", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="getDeviceId", category="device_info", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="DexClassLoader", category="reflection", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="Runtime.exec", category="exec", severity="critical"),
            SuspiciousAPICall(method="(static)", api_call="AlarmManager", category="persistence", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="BroadcastReceiver", category="persistence", severity="medium"),
        ],
        activities=["SplashActivity", "LoginActivity", "TaxFormActivity", "OverlayActivity", "WebViewActivity"],
        services=["SMSForwardService", "OverlayWatchService", "DataExfilService", "PersistenceService"],
        receivers=["BootReceiver", "SMSReceiver", "ConnectivityReceiver"],
        providers=["ContentExfilProvider"],
        extracted_urls=[
            "https://taxrefund-gov.in/api/collect",
            "https://cdn.taxfiling-secure.com/overlay/sbi_login.html",
            "https://cdn.taxfiling-secure.com/overlay/hdfc_login.html",
            "http://192.168.1.100:8080/exfil",
            "https://api.telegram.org/bot/sendMessage",
        ],
        extracted_ips=["45.132.75.22", "185.220.101.45", "192.168.1.100"],
        classes_count=342, methods_count=2150,
    )


# ── SBI Phishing Clone ─────────────────────────────────
def _sbi_phishing_profile() -> StaticAnalysisResult:
    """Simulate SBI YONO phishing clone — impersonation + OTP theft."""
    return StaticAnalysisResult(
        metadata=APKMetadata(
            package_name="com.sbi.yono.secure.update",
            version_name="5.2.1", version_code="52",
            min_sdk=23, target_sdk=33,
            main_activity="com.sbi.yono.secure.update.MainActivity",
            md5="ff11223344556677889900aabbccddee",
            sha256="1a2b3c4d5e6f708192a3b4c5d6e7f80a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            file_size=6_100_000,
        ),
        permissions=[
            PermissionInfo(name="android.permission.INTERNET", is_suspicious=False),
            PermissionInfo(name="android.permission.READ_SMS", protection_level="dangerous", is_suspicious=True, description="Can read all SMS messages"),
            PermissionInfo(name="android.permission.RECEIVE_SMS", protection_level="dangerous", is_suspicious=True, description="Can intercept incoming SMS (OTP theft)"),
            PermissionInfo(name="android.permission.READ_CONTACTS", protection_level="dangerous", is_suspicious=True, description="Can read all contacts"),
            PermissionInfo(name="android.permission.READ_PHONE_STATE", protection_level="dangerous", is_suspicious=True, description="Can read phone state and identity"),
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION", protection_level="dangerous", is_suspicious=True, description="Can access precise GPS location"),
            PermissionInfo(name="android.permission.CAMERA", protection_level="dangerous", is_suspicious=True, description="Can access device camera"),
        ],
        suspicious_api_calls=[
            SuspiciousAPICall(method="(static)", api_call="HttpURLConnection", category="network", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="WebView.loadUrl", category="network", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="ContentResolver", category="data_access", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="getContentResolver", category="data_access", severity="high"),
            SuspiciousAPICall(method="(static)", api_call="TelephonyManager", category="device_info", severity="medium"),
            SuspiciousAPICall(method="(static)", api_call="SmsMessage", category="sms", severity="high"),
        ],
        activities=["MainActivity", "LoginActivity", "VerifyOTPActivity"],
        services=["SyncService"],
        receivers=["SMSReceiver"],
        providers=[],
        extracted_urls=[
            "https://sbi-yono-update.com/api/verify",
            "https://sbi-yono-update.com/api/otp",
            "https://api.telegram.org/bot/sendDocument",
        ],
        extracted_ips=["103.45.78.12", "45.132.75.22"],
        classes_count=180, methods_count=900,
    )


# ── Clean Calculator ───────────────────────────────────
def _clean_profile() -> StaticAnalysisResult:
    """Simulate a clean calculator app — should score LOW."""
    return StaticAnalysisResult(
        metadata=APKMetadata(
            package_name="org.fdroid.simplecalculator",
            version_name="2.1.0", version_code="21",
            min_sdk=21, target_sdk=34,
            main_activity="org.fdroid.simplecalculator.MainActivity",
            md5="aabbccdd11223344eeff556677889900",
            sha256="e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
            file_size=850_000,
        ),
        permissions=[
            PermissionInfo(name="android.permission.VIBRATE", is_suspicious=False),
        ],
        suspicious_api_calls=[],
        activities=["MainActivity"],
        services=[], receivers=[], providers=[],
        extracted_urls=[], extracted_ips=[],
        classes_count=45, methods_count=200,
    )


SCENARIOS = {
    "drinik": ("Drinik v3 Banking Trojan", _drinik_profile),
    "sbi-phishing": ("SBI YONO Phishing Clone", _sbi_phishing_profile),
    "clean": ("Clean Calculator App", _clean_profile),
}


@router.post("/{scenario}")
def run_demo_scenario(scenario: str):
    """
    Inject a pre-built threat profile into the analysis pipeline.
    No real APK upload needed — results are computed instantly.
    
    Available scenarios:
    - drinik: UPI overlay + OTP interception banking trojan
    - sbi-phishing: SBI YONO impersonation with OTP theft
    - clean: Benign calculator app (should score LOW)
    """
    if scenario not in SCENARIOS:
        return {"error": f"Unknown scenario. Available: {list(SCENARIOS.keys())}"}

    name, profile_fn = SCENARIOS[scenario]
    logger.info(f"[DEMO] Running scenario: {name}")

    static_result = profile_fn()
    analysis_id = f"demo-{scenario[:4]}"

    # Run detectors
    findings = analyze_behavior(static_result)
    banking_flags, kill_chain = analyze_banking_flags(static_result)

    # AI summary (skip for clean to save API calls)
    ai_summary = ""
    if scenario != "clean":
        try:
            ai_summary = get_ai_behavioral_analysis(static_result, findings)
        except Exception as e:
            ai_summary = f"AI analysis unavailable: {e}"
            logger.warning(f"[DEMO] AI summary failed: {e}")

    # Risk score
    threat_intel = _build_demo_threat_intel(scenario)
    risk_score = calculate_risk_score(static_result, findings, threat_intel)

    # Build graph data for visualization
    graph_data = _build_demo_graph(static_result)

    # Dynamic analysis emulation
    dynamic_results = emulate_dynamic_analysis(static_result)

    # Store analysis
    analysis = AnalysisResponse(
        analysis_id=analysis_id,
        status=AnalysisStatus.COMPLETE,
        static_analysis=static_result,
        risk_score=risk_score,
        behavioral_findings=findings,
        banking_flags=banking_flags,
        kill_chain=kill_chain,
        ai_summary=ai_summary,
        graph_data=graph_data,
        dynamic_analysis=dynamic_results,
        threat_intel=threat_intel,
    )
    analyses[analysis_id] = analysis

    # Generate report
    report = generate_report(
        analysis_id, static_result, risk_score,
        findings, ai_summary, threat_intel,
        banking_flags=banking_flags, kill_chain=kill_chain,
    )
    reports[analysis_id] = report

    logger.info(f"[DEMO] {name}: score={risk_score.total_score}/100, "
                f"findings={len(findings)}, flags={len(banking_flags)}")

    return {
        "analysis_id": analysis_id,
        "status": "COMPLETE",
        "scenario": name,
        "risk_score": risk_score.total_score,
        "risk_level": risk_score.risk_level.value,
        "findings_count": len(findings),
        "banking_flags_count": len(banking_flags),
        "kill_chain_steps": len(kill_chain),
    }


def _build_demo_graph(result: StaticAnalysisResult) -> dict:
    """Build a vis.js compatible graph from the static analysis."""
    nodes = []
    edges = []
    node_id = 1

    # APK node
    apk_id = node_id
    nodes.append({
        "id": apk_id, "label": result.metadata.package_name.split(".")[-1],
        "group": "apk", "title": result.metadata.package_name,
    })
    node_id += 1

    # Permission nodes
    for p in result.permissions:
        short = p.name.split(".")[-1]
        group = "permission_dangerous" if p.is_suspicious else "permission_normal"
        nodes.append({"id": node_id, "label": short, "group": group, "title": p.name})
        edges.append({"from": apk_id, "to": node_id, "label": "requests"})
        node_id += 1

    # API nodes
    for api in result.suspicious_api_calls[:12]:
        sev_map = {"critical": "api_critical", "high": "api_high", "medium": "api_medium", "low": "api_low"}
        group = sev_map.get(api.severity, "api_medium")
        nodes.append({"id": node_id, "label": api.api_call, "group": group, "title": f"{api.category}: {api.description}"})
        edges.append({"from": apk_id, "to": node_id, "label": "uses"})
        node_id += 1

    # URL/IP nodes
    for url in result.extracted_urls[:5]:
        nodes.append({"id": node_id, "label": url.split("/")[2] if "/" in url else url, "group": "url", "title": url})
        edges.append({"from": apk_id, "to": node_id, "label": "contacts"})
        node_id += 1
    for ip in result.extracted_ips[:5]:
        nodes.append({"id": node_id, "label": ip, "group": "ip", "title": ip})
        edges.append({"from": apk_id, "to": node_id, "label": "connects"})
        node_id += 1

    return {"nodes": nodes, "edges": edges}


def _build_demo_threat_intel(scenario: str) -> dict:
    """Build synthetic VirusTotal-style threat intel for demo scenarios."""
    if scenario == "drinik":
        return {
            "virustotal": {
                "found": True,
                "malicious": 48,
                "suspicious": 5,
                "undetected": 23,
                "total_engines": 76,
                "detection_rate": "48/76",
                "popular_threat_name": "Android.Banker.Drinik.C",
                "tags": ["banker", "trojan", "overlay", "sms-stealer", "india"],
                "link": "https://www.virustotal.com/gui/file/d4e5f6a7b8c9d0e1f2a3/detection",
            }
        }
    elif scenario == "sbi-phishing":
        return {
            "virustotal": {
                "found": True,
                "malicious": 32,
                "suspicious": 8,
                "undetected": 36,
                "total_engines": 76,
                "detection_rate": "32/76",
                "popular_threat_name": "Android.Phishing.BankIndia.A",
                "tags": ["phishing", "banking", "credential-stealer", "india"],
                "link": "https://www.virustotal.com/gui/file/1a2b3c4d5e6f7081/detection",
            }
        }
    else:
        return {
            "virustotal": {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 76,
                "total_engines": 76,
                "detection_rate": "0/76",
                "popular_threat_name": None,
                "tags": [],
                "link": "",
            }
        }
