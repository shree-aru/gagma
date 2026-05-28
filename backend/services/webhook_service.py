"""
GAGMA Incident Response Webhook Service — SIEM / MDM Integration.

Automatically dispatches high-fidelity threat alert payloads to registered bank endpoints 
when high-priority risks or active banking trojan behaviors are detected.
"""
import logging
import asyncio
import httpx
from datetime import datetime, timezone
from services.database import get_system_setting

logger = logging.getLogger(__name__)

async def dispatch_webhook(event_type: str, payload: dict):
    """
    Asynchronously dispatch a threat incident payload to the configured SIEM/MDM webhook URL.
    """
    webhook_url = get_system_setting("webhook_url")
    if not webhook_url:
        logger.info("No SIEM/MDM webhook URL configured. Skipping dispatch.")
        return

    logger.info(f"Dispatching SIEM webhook event '{event_type}' to {webhook_url}")
    
    event_payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "security_level": "CRITICAL" if payload.get("risk_score", 0) >= 80 else "HIGH",
        "recommended_action": "LOCK_DEVICE" if payload.get("risk_score", 0) >= 80 else "QUARANTINE_APP",
        "data": payload
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(webhook_url, json=event_payload)
            if res.status_code >= 200 and res.status_code < 300:
                logger.info(f"SIEM Webhook dispatched successfully. Response: {res.status_code}")
            else:
                logger.error(f"SIEM Webhook failed with status: {res.status_code}")
    except Exception as e:
        logger.error(f"SIEM Webhook connection failed: {str(e)}")


async def test_webhook_connection(url: str) -> bool:
    """
    Sends a mock test payload to the target URL to verify active connectivity.
    """
    test_payload = {
        "event": "system.test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "security_level": "INFO",
        "recommended_action": "NONE",
        "data": {
            "message": "GAGMA Secure Webhook Gateway Test — SIEM/MDM connectivity verified successfully.",
            "status": "ONLINE"
        }
    }
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            res = await client.post(url, json=test_payload)
            return res.status_code >= 200 and res.status_code < 300
    except Exception:
        return False
