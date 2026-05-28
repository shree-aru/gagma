"""
GAGMA Webhook Router — Configure and test SIEM/MDM automated incident webhooks.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from backend.services.database import get_system_setting, save_system_setting, log_audit
from backend.services.webhook_service import test_webhook_connection

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

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
