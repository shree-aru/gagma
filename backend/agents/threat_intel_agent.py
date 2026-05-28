"""
GAGMA Threat Intelligence Agent — Enriches analysis with external
threat intelligence from VirusTotal and AbuseIPDB.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional

import httpx

from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

logger = logging.getLogger(__name__)


async def lookup_virustotal(sha256: str) -> Optional[dict]:
    """
    Look up an APK hash on VirusTotal.
    Returns detection results or None if unavailable.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.info("VirusTotal API key not configured — skipping lookup")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "detection_rate": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "popular_threat_name": attrs.get("popular_threat_classification", {}).get(
                        "suggested_threat_label", "Unknown"
                    ),
                    "tags": attrs.get("tags", []),
                    "first_seen": attrs.get("first_submission_date", ""),
                    "link": f"https://www.virustotal.com/gui/file/{sha256}",
                }
            elif response.status_code == 404:
                return {"found": False, "message": "File not found in VirusTotal database"}
            else:
                logger.warning(f"VirusTotal API returned {response.status_code}")
                return None

    except Exception as e:
        logger.error(f"VirusTotal lookup failed: {e}")
        return None


async def lookup_ip_reputation(ip: str) -> Optional[dict]:
    """
    Check an IP address against AbuseIPDB.
    Returns reputation data or None if unavailable.
    """
    if not ABUSEIPDB_API_KEY:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "total_reports": data.get("totalReports", 0),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                }
            return None

    except Exception as e:
        logger.error(f"AbuseIPDB lookup failed: {e}")
        return None


async def enrich_analysis(sha256: str, ips: list[str]) -> dict:
    """
    Run all threat intelligence lookups and return enriched data.
    """
    result = {
        "virustotal": None,
        "ip_reputations": [],
        "threat_level": "unknown",
    }

    # VirusTotal lookup
    vt_result = await lookup_virustotal(sha256)
    if vt_result:
        result["virustotal"] = vt_result
        if vt_result.get("found") and vt_result.get("malicious", 0) > 5:
            result["threat_level"] = "confirmed_malicious"
        elif vt_result.get("found") and vt_result.get("malicious", 0) > 0:
            result["threat_level"] = "suspicious"

    # IP reputation checks (limit to first 5)
    for ip in ips[:5]:
        ip_result = await lookup_ip_reputation(ip)
        if ip_result:
            result["ip_reputations"].append(ip_result)
            if ip_result.get("abuse_confidence_score", 0) > 50:
                result["threat_level"] = "suspicious"

    return result
