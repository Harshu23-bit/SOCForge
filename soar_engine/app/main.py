from fastapi import FastAPI, Request, HTTPException
import logging
from app.config import settings
from app.enrichment import extract_hash_from_payload, get_virustotal_hash_report
from app.llm_triage import analyze_alert_with_llm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("socforge-soar")

app = FastAPI(
    title="SOCForge SOAR Microservice",
    version="1.0.0",
    description="Autonomous AI SOC Triage Engine"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "socforge-soar"}

@app.post("/api/v1/triage")
async def receive_wazuh_alert(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    rule = payload.get("rule", {})
    agent = payload.get("agent", {})
    
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", 0)
    agent_name = agent.get("name", "unknown")
    description = rule.get("description", "No description provided")

    # Step 1: Extract Hash & Query VirusTotal
    file_hash = extract_hash_from_payload(payload)
    vt_report = None
    if file_hash:
        logger.info(f"Extracting payload hash: {file_hash}. Querying Threat Intel...")
        vt_report = await get_virustotal_hash_report(file_hash)

    # Compile enriched bundle for AI analysis
    enriched_telemetry = {
        "agent": agent_name,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description,
        "hash": file_hash,
        "virustotal": vt_report,
        "raw_payload": payload
    }

    # Step 2: Execute AI Triage Analysis
    logger.info("Triggering Gemini AI Triage Engine...")
    ai_triage = analyze_alert_with_llm(enriched_telemetry)

    return {
        "status": "triaged",
        "agent": agent_name,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description,
        "hash": file_hash,
        "virustotal": vt_report,
        "ai_triage": ai_triage.model_dump()
    }
