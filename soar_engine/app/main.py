from fastapi import FastAPI, Request, HTTPException
import logging
from app.config import settings

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

    # Extract core telemetry metadata
    rule = payload.get("rule", {})
    agent = payload.get("agent", {})
    
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", 0)
    agent_name = agent.get("name", "unknown")
    description = rule.get("description", "No description provided")

    logger.info(f"Alert Ingested | Agent: {agent_name} | Rule SID: {rule_id} | Level: {rule_level}")

    return {
        "status": "ingested",
        "agent": agent_name,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description
    }
