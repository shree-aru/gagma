"""
GAGMA YARA Signature Generator Service.

Generates highly syntactically valid and deployable YARA rules tailored to analyzed 
Android packages, helping banking security teams identify threat vectors in the wild.
"""
from datetime import datetime, timezone

def generate_yara_rule(analysis_id: str, data: dict) -> str:
    """
    Dynamically generates a custom YARA rule based on static, dynamic, and behavior threat parameters.
    """
    static = data.get("static_analysis", {})
    metadata = static.get("metadata", {})
    
    package_name = metadata.get("package_name", "com.unknown.malware")
    sha256 = metadata.get("sha256", "")
    risk_score = data.get("risk_score", {}).get("total_score", 0)
    risk_level = data.get("risk_score", {}).get("risk_level", "UNKNOWN")
    
    # Safe rule name formatting
    rule_name_suffix = sha256[:16] if sha256 else "Generic"
    rule_name = f"GAGMA_Malware_Threat_{rule_name_suffix}"
    
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Select interesting strings for YARA signatures
    # 1. Accessibility Service check
    accessibility_check = False
    sms_check = False
    
    strings = []
    
    # Add Package Name string
    strings.append(f'        $pkg_name = "{package_name}" ascii')
    
    # Check permissions for accessibility overlays or banking interceptors
    permissions = static.get("permissions", [])
    suspicious_apis = static.get("suspicious_api_calls", [])
    
    for perm in permissions:
        name = perm.get("name", "")
        if "BIND_ACCESSIBILITY_SERVICE" in name:
            accessibility_check = True
            strings.append('        $accessibility_service = "android.accessibilityservice.AccessibilityService" ascii')
        if "SEND_SMS" in name or "RECEIVE_SMS" in name:
            sms_check = True
            strings.append('        $sms_manager = "android.telephony.SmsManager" ascii')
            
    # IP/Domain Indicators
    extracted_ips = static.get("extracted_ips", [])
    ip_count = 0
    for ip in extracted_ips[:3]:
        ip_count += 1
        strings.append(f'        $network_ip_{ip_count} = "{ip}" ascii')
        
    # Standard dangerous APIs
    api_count = 0
    for api in suspicious_apis[:3]:
        api_count += 1
        strings.append(f'        $suspicious_api_{api_count} = "{api}" ascii')

    # Compile condition block
    conditions = ["$pkg_name"]
    if accessibility_check:
        conditions.append("$accessibility_service")
    if sms_check:
        conditions.append("$sms_manager")
    if ip_count > 0:
        conditions.append(f"any of ($network_ip_*)")
    if api_count > 0:
        conditions.append(f"1 of ($suspicious_api_*)")
        
    condition_str = " or ".join(conditions)

    # Format final YARA rule
    rule_body = f"""/*
  GAGMA Threat Intelligence Rule
  Generated automatically by GAGMA Malware Command Center.
*/

rule {rule_name} {{
    meta:
        description = "Detects threat vectors associated with {package_name}"
        author = "GAGMA Autonomous Malware Analyst v2.0"
        reference = "http://3.229.117.157/analysis/{analysis_id}"
        date = "{date_str}"
        sha256 = "{sha256}"
        risk_score = {risk_score}
        risk_level = "{risk_level}"

    strings:
{chr(10).join(strings)}

    condition:
        {condition_str}
}}
"""
    return rule_body
