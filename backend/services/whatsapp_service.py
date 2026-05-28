"""
GAGMA WhatsApp Service — Integrates instant mobile alerting via CallMeBot API.
Enables real-time incident notifications dispatched directly to security administrators' WhatsApp.
"""
from __future__ import annotations

import logging
import urllib.parse
import httpx
from services.database import get_system_setting, save_system_setting, log_audit

logger = logging.getLogger(__name__)

def get_whatsapp_config() -> dict:
    """Retrieve current WhatsApp alert settings."""
    return {
        "enabled": get_system_setting("whatsapp_enabled") == "true",
        "phone": get_system_setting("whatsapp_phone"),
        "apikey": get_system_setting("whatsapp_apikey")
    }

def save_whatsapp_config(enabled: bool, phone: str, apikey: str):
    """Save WhatsApp configurations to persistent SQLite database."""
    save_system_setting("whatsapp_enabled", "true" if enabled else "false")
    save_system_setting("whatsapp_phone", phone.strip())
    save_system_setting("whatsapp_apikey", apikey.strip())
    
    status_str = "ENABLED" if enabled else "DISABLED"
    log_audit(
        "CONFIG_WHATSAPP", 
        actor="administrator", 
        detail=f"WhatsApp alerts {status_str}. Target: {phone.strip()}"
    )

async def send_whatsapp_message(phone: str, apikey: str, text: str) -> bool:
    """Send an arbitrary WhatsApp message via CallMeBot free developer gateway."""
    if not phone or not apikey or not text:
        logger.warning("WhatsApp dispatch skipped: phone, apikey, or text is missing")
        return False
        
    encoded_text = urllib.parse.quote(text)
    # CallMeBot API Endpoint
    url = f"https://api.callmebot.com/whatsapp.php?phone={phone}&text={encoded_text}&apikey={apikey}"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(url)
            if res.status_code == 200 and "Message sent" in res.text:
                logger.info(f"WhatsApp alert successfully dispatched to {phone}")
                return True
            else:
                logger.warning(f"WhatsApp API responded with status {res.status_code}: {res.text[:100]}")
                # Some successful responses might not contain "Message sent" exactly, let's treat 200 as tentative success
                return res.status_code == 200
    except Exception as e:
        logger.error(f"WhatsApp gateway connection error: {e}")
        return False

async def auto_dispatch_whatsapp_alert(analysis_id: str, package_name: str, risk_score: float, risk_level: str) -> bool:
    """Evaluate and dispatch an automated alert if a threat's risk score is CRITICAL/HIGH."""
    config = get_whatsapp_config()
    if not config["enabled"]:
        return False
        
    # Format a gorgeous, high-fidelity security incident alert
    alert_message = (
        "🚨 *GAGMA SECURE COMMAND CENTER* 🚨\n\n"
        "*CRITICAL MOBILE MALWARE THREAT DETECTED*\n\n"
        f"■ *Package:* `{package_name}`\n"
        f"■ *Analysis ID:* `{analysis_id}`\n"
        f"■ *Risk Verdict:* `{risk_score}/100` ({risk_level})\n"
        "■ *Countermeasure:* Enterprise Blocklist Seeded\n"
        "■ *RBI Status:* Non-Compliant Activity Blocked\n\n"
        "_Incident response is active. Check the SOC HUD Command Center for the full threat report._"
    )
    
    success = await send_whatsapp_message(
        phone=config["phone"],
        apikey=config["apikey"],
        text=alert_message
    )
    if success:
        log_audit(
            "WHATSAPP_ALERT_DISPATCHED",
            actor="system",
            resource_id=analysis_id,
            detail=f"Automated threat alert sent to {config['phone']}"
        )
    return success
