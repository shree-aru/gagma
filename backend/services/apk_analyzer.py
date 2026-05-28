"""
GAGMA APK Analyzer — Static analysis using androguard
Extracts permissions, API calls, call graphs, URLs, IPs, and metadata.
Falls back to zipfile-based extraction if androguard is unavailable.
"""
from __future__ import annotations

import hashlib
import re
import zipfile
import logging
from pathlib import Path
from typing import Optional

from models.schemas import (
    APKMetadata,
    PermissionInfo,
    StaticAnalysisResult,
    SuspiciousAPICall,
)

logger = logging.getLogger(__name__)

# ── Performance tuning ─────────────────────────────────
# Max call-graph edges to iterate (prevents multi-minute scans)
MAX_CALL_EDGES = 30_000
# Library prefixes to skip in call graph (not interesting for malware)
LIBRARY_PREFIXES = (
    "Landroid/support/",
    "Landroidx/",
    "Lcom/google/android/gms/",
    "Lcom/google/android/material/",
    "Lcom/google/firebase/",
    "Lcom/google/protobuf/",
    "Lcom/google/gson/",
    "Lokhttp3/",
    "Lretrofit2/",
    "Lorg/apache/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lcom/squareup/",
    "Lio/reactivex/",
    "Lcom/fasterxml/",
)

# ── Dangerous permissions classification ───────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}

# ── Suspicious API patterns ───────────────────────────
SUSPICIOUS_API_PATTERNS = {
    "sms": [
        r"SmsManager",
        r"sendTextMessage",
        r"sendMultipartTextMessage",
        r"android\.telephony\.SmsMessage",
        r"content://sms",
    ],
    "crypto": [
        r"javax\.crypto",
        r"Cipher\.getInstance",
        r"SecretKeySpec",
        r"KeyGenerator",
        r"MessageDigest",
    ],
    "network": [
        r"HttpURLConnection",
        r"OkHttpClient",
        r"URLConnection",
        r"Socket\(",
        r"ServerSocket",
        r"DatagramSocket",
        r"InetAddress",
        r"WebView\.loadUrl",
    ],
    "reflection": [
        r"Class\.forName",
        r"Method\.invoke",
        r"getDeclaredMethod",
        r"getDeclaredField",
        r"setAccessible",
        r"ClassLoader",
        r"DexClassLoader",
        r"PathClassLoader",
    ],
    "exec": [
        r"Runtime\.getRuntime\(\)\.exec",
        r"ProcessBuilder",
        r"Runtime\.exec",
        r"su\b",
    ],
    "data_access": [
        r"ContentResolver",
        r"getContentResolver",
        r"ContactsContract",
        r"CallLog",
        r"content://contacts",
        r"content://call_log",
        r"content://calendar",
    ],
    "device_info": [
        r"TelephonyManager",
        r"getDeviceId",
        r"getSubscriberId",
        r"getSimSerialNumber",
        r"getLine1Number",
        r"Build\.SERIAL",
        r"Build\.FINGERPRINT",
        r"Settings\.Secure\.ANDROID_ID",
    ],
    "overlay": [
        r"TYPE_APPLICATION_OVERLAY",
        r"TYPE_SYSTEM_ALERT",
        r"TYPE_SYSTEM_OVERLAY",
        r"WindowManager\.LayoutParams",
    ],
    "accessibility": [
        r"AccessibilityService",
        r"AccessibilityEvent",
        r"onAccessibilityEvent",
        r"performAction",
    ],
    "persistence": [
        r"AlarmManager",
        r"JobScheduler",
        r"WorkManager",
        r"RECEIVE_BOOT_COMPLETED",
        r"BroadcastReceiver",
    ],
}

# ── URL/IP extraction patterns ─────────────────────────
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'}\)\\]{4,}',
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def compute_hashes(file_path: Path) -> tuple[str, str]:
    """Compute MD5 and SHA256 of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _classify_permission(perm: str) -> PermissionInfo:
    """Classify a permission as dangerous/normal with description."""
    short_name = perm.split(".")[-1] if "." in perm else perm
    is_dangerous = perm in DANGEROUS_PERMISSIONS

    descriptions = {
        "READ_SMS": "Can read all SMS messages",
        "SEND_SMS": "Can send SMS messages (potential premium SMS fraud)",
        "RECEIVE_SMS": "Can intercept incoming SMS (OTP theft)",
        "READ_CONTACTS": "Can read all contacts",
        "READ_CALL_LOG": "Can read call history",
        "READ_PHONE_STATE": "Can read phone state and identity",
        "CALL_PHONE": "Can make phone calls",
        "CAMERA": "Can access device camera",
        "RECORD_AUDIO": "Can record audio",
        "ACCESS_FINE_LOCATION": "Can access precise GPS location",
        "SYSTEM_ALERT_WINDOW": "Can draw overlays on top of other apps",
        "BIND_ACCESSIBILITY_SERVICE": "Can monitor and control UI (keylogging risk)",
        "BIND_DEVICE_ADMIN": "Can gain device administrator privileges",
        "REQUEST_INSTALL_PACKAGES": "Can install other APKs",
        "RECEIVE_BOOT_COMPLETED": "Starts automatically on device boot",
        "INTERNET": "Can access the internet",
    }

    return PermissionInfo(
        name=perm,
        protection_level="dangerous" if is_dangerous else "normal",
        description=descriptions.get(short_name, ""),
        is_suspicious=is_dangerous,
    )


def _extract_strings_from_dex(file_path: Path) -> list[str]:
    """Extract readable strings from DEX files inside the APK."""
    strings = []
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex"):
                    data = zf.read(name)
                    # Extract printable ASCII strings of length >= 6
                    found = re.findall(rb'[\x20-\x7e]{6,}', data)
                    strings.extend(s.decode("ascii", errors="ignore") for s in found)
    except Exception as e:
        logger.warning(f"String extraction failed: {e}")
    return strings


def _find_suspicious_apis(strings: list[str]) -> list[SuspiciousAPICall]:
    """Scan extracted strings for suspicious API patterns."""
    findings: list[SuspiciousAPICall] = []
    seen = set()

    severity_map = {
        "sms": "high",
        "crypto": "medium",
        "network": "medium",
        "reflection": "high",
        "exec": "critical",
        "data_access": "high",
        "device_info": "medium",
        "overlay": "high",
        "accessibility": "critical",
        "persistence": "medium",
    }

    for category, patterns in SUSPICIOUS_API_PATTERNS.items():
        for pattern in patterns:
            compiled = re.compile(pattern)
            for s in strings:
                if compiled.search(s):
                    key = (category, pattern)
                    if key not in seen:
                        seen.add(key)
                        findings.append(SuspiciousAPICall(
                            method="(static extraction)",
                            api_call=pattern.replace("\\", ""),
                            category=category,
                            severity=severity_map.get(category, "medium"),
                            description=f"Detected {category} API usage: {pattern}",
                        ))
    return findings


def analyze_apk(file_path: Path) -> StaticAnalysisResult:
    """
    Perform comprehensive static analysis on an APK file.
    Uses androguard if available, falls back to zipfile-based extraction.
    """
    result = StaticAnalysisResult()
    file_path = Path(file_path)

    # ── File hashes ────────────────────────────────────
    md5, sha256 = compute_hashes(file_path)
    result.metadata.md5 = md5
    result.metadata.sha256 = sha256
    result.metadata.file_size = file_path.stat().st_size

    # ── Try androguard first ───────────────────────────
    try:
        from androguard.core.apk import APK as _APK  # noqa: F401
        logger.info("Using androguard for fast analysis (two-tier)")
        result = _analyze_with_androguard(file_path, result)
    except ImportError:
        logger.warning("androguard not installed, using fallback extraction")
        result = _analyze_fallback(file_path, result)

    return result


def _get_method_name(method_or_analysis) -> tuple[str, str]:
    """Safely extract (class_name, method_name) from either EncodedMethod or MethodAnalysis."""
    # Try direct access first (EncodedMethod)
    if hasattr(method_or_analysis, 'get_name'):
        return method_or_analysis.get_class_name(), method_or_analysis.get_name()
    # MethodAnalysis wraps an EncodedMethod via .get_method()
    if hasattr(method_or_analysis, 'get_method'):
        m = method_or_analysis.get_method()
        if m and hasattr(m, 'get_name'):
            return m.get_class_name(), m.get_name()
    # Last resort: use string representation
    name = str(method_or_analysis)
    return ("", name)


def _is_library_class(class_name: str) -> bool:
    """Check if a class belongs to a known library (skip in call graph)."""
    return class_name.startswith(LIBRARY_PREFIXES)


def _analyze_with_androguard(file_path: Path, result: StaticAnalysisResult) -> StaticAnalysisResult:
    """
    Fast two-tier analysis using androguard — OPTIMIZED for speed.

    Instead of calling AnalyzeAPK() (which builds expensive cross-reference
    analysis taking 5+ minutes), we use:
      Tier 1: APK() for metadata/permissions/components  (~1-2s)
      Tier 2: DalvikVMFormat for class/method counting    (~5-10s)
      Tier 3: String-based suspicious API detection        (~3-5s)

    Total: ~15-30 seconds instead of ~300+ seconds.
    """
    import time
    t0 = time.perf_counter()

    # Suppress verbose androguard debug logging (v4 uses loguru)
    logging.getLogger("androguard").setLevel(logging.WARNING)
    logging.getLogger("androguard.core").setLevel(logging.WARNING)
    logging.getLogger("androguard.core.analysis").setLevel(logging.WARNING)
    try:
        from loguru import logger as loguru_logger
        loguru_logger.disable("androguard")
    except ImportError:
        pass

    # ── Tier 1: Fast metadata via APK() — manifest only ──
    from androguard.core.apk import APK

    logger.info("Tier 1: Parsing APK manifest (fast)...")
    a = APK(str(file_path))
    t1 = time.perf_counter()
    logger.info(f"Tier 1: APK manifest parsed in {t1-t0:.1f}s")

    # Metadata
    result.metadata.package_name = a.get_package() or ""
    result.metadata.version_name = a.get_androidversion_name() or ""
    result.metadata.version_code = a.get_androidversion_code() or ""
    result.metadata.min_sdk = int(a.get_min_sdk_version() or 0)
    result.metadata.target_sdk = int(a.get_target_sdk_version() or 0)
    result.metadata.main_activity = a.get_main_activity() or ""

    # Permissions
    perms = a.get_permissions() or []
    result.permissions = [_classify_permission(p) for p in perms]

    # Components
    result.activities = list(a.get_activities() or [])
    result.services = list(a.get_services() or [])
    result.receivers = list(a.get_receivers() or [])
    result.providers = list(a.get_providers() or [])

    logger.info(f"Tier 1: {len(perms)} permissions, "
                f"{len(result.activities)} activities, "
                f"{len(result.services)} services")

    # ── Tier 2: DEX structure parsing (no xref analysis) ──
    logger.info("Tier 2: Parsing DEX structure (no cross-reference)...")
    t2_start = time.perf_counter()

    total_classes = 0
    total_methods = 0

    try:
        from androguard.core.dex import DEX

        for dex_bytes in a.get_all_dex():
            try:
                dvm = DEX(dex_bytes)
                classes = dvm.get_classes()
                methods = dvm.get_methods()
                total_classes += len(classes)
                total_methods += len(methods)
            except Exception as e:
                logger.warning(f"DEX parsing error: {e}")
                continue
    except Exception as e:
        logger.warning(f"Tier 2 DVM parsing failed, continuing: {e}")

    result.classes_count = total_classes
    result.methods_count = total_methods

    t2 = time.perf_counter()
    logger.info(f"Tier 2: {total_classes} classes, {total_methods} methods "
                f"in {t2-t2_start:.1f}s")

    # ── Tier 3: String-based API detection + URL/IP extraction ──
    logger.info("Tier 3: String-based suspicious API detection...")
    t3_start = time.perf_counter()

    all_strings = _extract_strings_from_dex(file_path)
    combined = " ".join(all_strings)
    result.extracted_urls = list(set(URL_PATTERN.findall(combined)))
    result.extracted_ips = list(set(
        ip for ip in IP_PATTERN.findall(combined)
        if not ip.startswith("0.") and not ip.startswith("127.")
        and ip != "255.255.255.255" and ip != "0.0.0.0"
    ))
    # Keep only potentially interesting strings (not too long, not too short)
    result.extracted_strings = [
        s for s in all_strings
        if 8 <= len(s) <= 200 and not s.startswith("//") and " " not in s[:5]
    ][:200]  # Cap at 200 to avoid flooding

    # String-based suspicious API detection
    result.suspicious_api_calls = _find_suspicious_apis(all_strings)

    t3 = time.perf_counter()
    logger.info(f"Tier 3: {len(result.suspicious_api_calls)} suspicious APIs, "
                f"{len(result.extracted_urls)} URLs, "
                f"{len(result.extracted_ips)} IPs "
                f"in {t3-t3_start:.1f}s")

    total_time = t3 - t0
    logger.info(f"✅ Total APK analysis completed in {total_time:.1f}s "
                f"(was ~300s+ with AnalyzeAPK)")
    return result


def _analyze_fallback(file_path: Path, result: StaticAnalysisResult) -> StaticAnalysisResult:
    """Fallback analysis using zipfile + XML parsing when androguard is unavailable."""
    import xml.etree.ElementTree as ET

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            # Try to parse AndroidManifest.xml (binary XML, may not work without axmlprinter)
            if "AndroidManifest.xml" in zf.namelist():
                try:
                    manifest_data = zf.read("AndroidManifest.xml")
                    # Try text parse (works if manifest is in plain XML, e.g., from apktool)
                    root = ET.fromstring(manifest_data)
                    ns = {"android": "http://schemas.android.com/apk/res/android"}

                    result.metadata.package_name = root.get("package", "")

                    for perm in root.findall(".//uses-permission"):
                        pname = perm.get(f"{{{ns['android']}}}name", "")
                        if pname:
                            result.permissions.append(_classify_permission(pname))

                    for act in root.findall(".//activity"):
                        aname = act.get(f"{{{ns['android']}}}name", "")
                        if aname:
                            result.activities.append(aname)

                    for svc in root.findall(".//service"):
                        sname = svc.get(f"{{{ns['android']}}}name", "")
                        if sname:
                            result.services.append(sname)

                    for rcv in root.findall(".//receiver"):
                        rname = rcv.get(f"{{{ns['android']}}}name", "")
                        if rname:
                            result.receivers.append(rname)

                except ET.ParseError:
                    logger.warning("Could not parse AndroidManifest.xml (binary format)")
                    # Still try to extract info from DEX strings
                    pass

    except zipfile.BadZipFile:
        logger.error(f"Invalid APK/ZIP file: {file_path}")

    # ── String-based analysis (always works) ───────────
    all_strings = _extract_strings_from_dex(file_path)
    result.extracted_urls = list(set(URL_PATTERN.findall(" ".join(all_strings))))
    result.extracted_ips = list(set(
        ip for ip in IP_PATTERN.findall(" ".join(all_strings))
        if not ip.startswith("0.") and not ip.startswith("127.")
    ))
    result.suspicious_api_calls = _find_suspicious_apis(all_strings)
    result.extracted_strings = [
        s for s in all_strings if 8 <= len(s) <= 200
    ][:200]

    return result
