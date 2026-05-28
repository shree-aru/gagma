"""
Verification script for GAGMA Phase 1 Detects — UPI Overlay and OTP Interception.
"""
from models.schemas import StaticAnalysisResult, PermissionInfo, SuspiciousAPICall, APKMetadata
from agents.behavior_agent import analyze_behavior, analyze_banking_flags

def run_test():
    print("==========================================================")
    print("STARTING GAGMA BANKING DETECTOR SIMULATION WORKFLOW")
    print("==========================================================")

    # 1. Simulate an Overlay + OTP Interception Banking Trojan (e.g., Drinik clone)
    trojan_metadata = APKMetadata(
        package_name="com.sbionline.securepay.india", # Suspicious, has "sbi" keyword but not verified
        version_name="1.0.4",
        version_code="5",
        sha256="bf2a9d8d672809e3e2b2f6b8b0e9c81122a2a3a4a5a6a7a8a9a0b1c2d3e4f5a6"
    )

    trojan_permissions = [
        PermissionInfo(name="android.permission.INTERNET", protection_level="normal", is_suspicious=False),
        PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW", protection_level="dangerous", is_suspicious=True),
        PermissionInfo(name="android.permission.BIND_ACCESSIBILITY_SERVICE", protection_level="signature", is_suspicious=True),
        PermissionInfo(name="android.permission.RECEIVE_SMS", protection_level="dangerous", is_suspicious=True),
        PermissionInfo(name="android.permission.READ_SMS", protection_level="dangerous", is_suspicious=True),
        PermissionInfo(name="android.permission.SEND_SMS", protection_level="dangerous", is_suspicious=True),
    ]

    trojan_apis = [
        SuspiciousAPICall(method="a", api_call="WindowManager.addView", category="overlay", severity="high"),
        SuspiciousAPICall(method="b", api_call="TYPE_APPLICATION_OVERLAY", category="overlay", severity="critical"),
        SuspiciousAPICall(method="c", api_call="AccessibilityService", category="reflection", severity="high"),
        SuspiciousAPICall(method="d", api_call="SmsMessage.createFromPdu", category="sms", severity="high"),
        SuspiciousAPICall(method="e", api_call="HttpURLConnection.getOutputStream", category="network", severity="medium"),
    ]

    trojan_result = StaticAnalysisResult(
        metadata=trojan_metadata,
        permissions=trojan_permissions,
        suspicious_api_calls=trojan_apis,
        classes_count=150,
        methods_count=1200
    )

    # 2. Run GAGMA's engines on simulated trojan
    print("\n[+] Feeding Simulated Trojan APK into GAGMA Behavioral Agent...")
    findings = analyze_behavior(trojan_result)
    banking_flags, kill_chain = analyze_banking_flags(trojan_result)

    # 3. Print Detections
    print("\n--- DETECTED BEHAVIORAL FINDINGS ---")
    for f in findings:
        print(f"  * {f.pattern_name} [{f.severity.upper()}]")
        print(f"    MITRE Tactics: {f.mitre_tactics}")
        print(f"    MITRE Techniques: {f.mitre_techniques}")

    print("\n--- DETECTED BANKING SECTOR FLAGS ---")
    for flag in banking_flags:
        print(f"  [!] {flag.severity.upper()} - {flag.title}")
        print(f"      Detail: {flag.detail[:100]}...")
        if flag.affected_apps:
            print(f"      Affected Apps: {', '.join(flag.affected_apps)}")

    print("\n--- RECONSTRUCTED KILL CHAIN TIMELINE ---")
    for step in kill_chain:
        print(f"  Stage {step.stage}: {step.name} (MITRE ID: {step.technique})")
        print(f"    {step.description[:90]}...")

    # 4. Verify specific test cases
    assert any(flag.flag_type == "APP_IMPERSONATION" for flag in banking_flags), "FAILED: App Impersonation not detected"
    assert any(flag.flag_type == "UPI_OVERLAY" for flag in banking_flags), "FAILED: UPI Overlay capability not detected"
    assert any(flag.flag_type == "OTP_INTERCEPTION" for flag in banking_flags), "FAILED: OTP Interception risk not detected"
    print("\n==========================================================")
    print("SUCCESS: ALL TEST CASES PASSED! NEW DETECTORS ARE 100% OPERATIONAL.")
    print("==========================================================")

if __name__ == "__main__":
    run_test()
