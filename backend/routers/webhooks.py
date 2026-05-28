"""
GAGMA Webhook Router — Configure and test SIEM/MDM automated incident webhooks and WhatsApp alerting.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from services.database import get_system_setting, save_system_setting, log_audit
from services.webhook_service import test_webhook_connection
from services.whatsapp_service import get_whatsapp_config, save_whatsapp_config, send_whatsapp_message

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

# ── SIEM Webhook Settings ──────────────────────────────
class WebhookConfig(BaseModel):
    url: str

@router.get("/config")
async def get_webhook_config():
    """Retrieve the current SIEM/MDM webhook URL."""
    url = get_system_setting("webhook_url")
    return {"url": url}

@router.post("/config")
async def save_webhook_config(config: WebhookConfig):
    """Save the SIEM/MDM webhook URL and audit log the change."""
    url = config.url.strip()
    save_system_setting("webhook_url", url)
    log_audit("CONFIG_WEBHOOK", actor="administrator", detail=f"SIEM Webhook URL updated to: {url}")
    return {"status": "success", "url": url}

@router.post("/test")
async def test_webhook(config: WebhookConfig):
    """Test connectivity by sending a system.test payload to the specified URL."""
    url = config.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Webhook URL cannot be empty")
        
    success = await test_webhook_connection(url)
    if success:
        log_audit("TEST_WEBHOOK", actor="administrator", detail=f"Webhook test passed for: {url}")
        return {"status": "success", "message": "Test payload delivered successfully!"}
    else:
        log_audit("TEST_WEBHOOK_FAILED", actor="administrator", detail=f"Webhook test failed for: {url}")
        raise HTTPException(status_code=502, detail="Failed to connect or receive 2xx response from target URL")


# ── WhatsApp Bot Settings ─────────────────────────────
class WhatsAppConfig(BaseModel):
    enabled: bool
    phone: str
    apikey: str

@router.get("/whatsapp")
async def get_wa_config():
    """Retrieve WhatsApp alert configuration."""
    return get_whatsapp_config()

@router.post("/whatsapp")
async def save_wa_config(config: WhatsAppConfig):
    """Update and persist WhatsApp configurations."""
    save_whatsapp_config(
        enabled=config.enabled,
        phone=config.phone,
        apikey=config.apikey
    )
    return {"status": "success", "config": get_whatsapp_config()}

@router.post("/whatsapp/test")
async def test_wa(config: WhatsAppConfig):
    """Trigger an instant manual test notification via WhatsApp."""
    phone = config.phone.strip()
    apikey = config.apikey.strip()
    
    if not phone or not apikey:
        raise HTTPException(status_code=400, detail="Phone number and API Key are required to run test")
        
    test_msg = (
        "🟢 *GAGMA SECURE COMMAND CENTER* 🟢\n\n"
        "This is an automated *Test Notification* from your GAGMA SOC Portal.\n"
        "Your WhatsApp incident alert gateway is fully *Connected & Active*!\n\n"
        "_Incident logs and real-time mobile payloads will deliver here._"
    )
    
    success = await send_whatsapp_message(phone=phone, apikey=apikey, text=test_msg)
    if success:
        log_audit("TEST_WHATSAPP", actor="administrator", detail=f"WhatsApp test alert delivered to {phone}")
        return {"status": "success", "message": "WhatsApp test notification sent successfully!"}
    else:
        log_audit("TEST_WHATSAPP_FAILED", actor="administrator", detail=f"WhatsApp test failed for {phone}")
        raise HTTPException(status_code=502, detail="Failed to deliver WhatsApp test message. Verify API key and phone number.")


# ── Telegram Bot Settings ──────────────────────────────
from services.telegram_service import get_telegram_config, save_telegram_config, send_telegram_message

class TelegramConfig(BaseModel):
    enabled: bool
    chat_id: str
    bot_token: str = ""

@router.get("/telegram")
async def get_tg_config():
    """Retrieve Telegram alert configuration."""
    return get_telegram_config()

@router.post("/telegram")
async def save_tg_config(config: TelegramConfig):
    """Update and persist Telegram configurations."""
    save_telegram_config(
        enabled=config.enabled,
        chat_id=config.chat_id,
        bot_token=config.bot_token
    )
    return {"status": "success", "config": get_telegram_config()}

@router.post("/telegram/test")
async def test_tg(config: TelegramConfig):
    """Trigger an instant manual test notification via Telegram Bot."""
    chat_id = config.chat_id.strip()
    
    if not chat_id:
        raise HTTPException(status_code=400, detail="Telegram Chat ID is required to run test")
        
    test_msg = (
        "🟢 *GAGMA SECURE COMMAND CENTER* 🟢\n\n"
        "This is an automated *Test Notification* from your GAGMA SOC Portal.\n"
        "Your Telegram incident alert gateway is fully *Connected & Active*!\n\n"
        "_Incident logs and real-time mobile payloads will deliver here._"
    )
    
    success = await send_telegram_message(chat_id=chat_id, text=test_msg, custom_token=config.bot_token)
    if success:
        log_audit("TEST_TELEGRAM", actor="administrator", detail=f"Telegram test alert delivered to Chat ID {chat_id}")
        return {"status": "success", "message": "Telegram test notification sent successfully!"}
    else:
        log_audit("TEST_TELEGRAM_FAILED", actor="administrator", detail=f"Telegram test failed for Chat ID {chat_id}")
        raise HTTPException(status_code=502, detail="Failed to deliver Telegram test message. Verify Chat ID.")
