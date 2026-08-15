import httpx
import logging
from app.config import settings

logger = logging.getLogger("socforge-soar")

async def get_virustotal_hash_report(file_hash: str) -> dict:
    """Query VirusTotal v3 API for file hash reputation."""
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API Key missing in environment settings.")
        return {"status": "skipped", "reason": "API key missing"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "status": "enriched",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attributes.get("reputation", 0),
                    "meaningful_name": attributes.get("meaningful_name", "N/A")
                }
            elif response.status_code == 404:
                return {"status": "not_found", "reason": "Hash not seen on VirusTotal"}
            else:
                logger.error(f"VirusTotal API Error: {response.status_code}")
                return {"status": "error", "code": response.status_code}
        except Exception as e:
            logger.error(f"Failed to query VirusTotal: {str(e)}")
            return {"status": "error", "reason": str(e)}

def extract_hash_from_payload(payload: dict) -> str | None:
    """Extract MD5/SHA256 hash from standard Wazuh alert fields."""
    syscheck = payload.get("syscheck", {})
    if "md5_after" in syscheck:
        return syscheck["md5_after"]
    if "sha256_after" in syscheck:
        return syscheck["sha256_after"]

    # Check raw data fields
    data = payload.get("data", {})
    if "hash" in data:
        return data["hash"]
    if "sha256" in data:
        return data["sha256"]

    return None
