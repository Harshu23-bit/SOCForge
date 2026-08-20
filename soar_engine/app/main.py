from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request

from .config import settings
from .enrichment import enrich_detection
from .incident import incident_store
from .ingestion import normalize_wazuh_alert
from .schemas import Incident
from .triage import triage_event
from .llm_triage import generate_ai_assessment
from .notifier import send_incident_to_discord
from .discord_interactions import router as discord_router

logger = logging.getLogger("socforge-soar")

app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description=(
        "SOCForge Security Orchestration, "
        "Automation and Response Engine"
    ),
)

app.include_router(discord_router)

@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "status": "online",
        "version": "0.2.0",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": settings.app_name,
    }


@app.post(
    "/api/v1/events/wazuh",
    response_model=Incident,
)
async def receive_wazuh_event(
    request: Request,
):
    try:
        payload = await request.json()

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Request body must contain valid JSON.",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="Wazuh event must be a JSON object.",
        )

    try:
        # 1. Normalize
        detection = normalize_wazuh_alert(
            payload
        )

        # 2. Enrich
        enrichment = await enrich_detection(
            detection
        )

        # 3. Deterministic triage
        triage = triage_event(
            detection,
            enrichment,
        )

        # 4. Create incident
        incident = incident_store.create(
            detection=detection,
            enrichment=enrichment,
            triage=triage,
        )

        # 5. Generate AI assessment
        ai_assessment = await generate_ai_assessment(
            incident
        )

        # 6. Attach AI assessment
        incident = incident_store.attach_ai_assessment(
            incident.incident_id,
            ai_assessment,
        )

        if incident is None:
            raise HTTPException(
                status_code=500,
                detail="Failed to attach AI assessment.",
            )

        # 7. Dispatch incident to Discord
        discord_message_id = (
            await send_incident_to_discord(
                incident
            )
        )

        if discord_message_id:
            incident = incident_store.attach_discord_message(
                incident.incident_id,
                discord_message_id,
            )

            if incident is None:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Failed to attach Discord "
                        "message metadata."
                    ),
                )

        incident.metadata["discord_dispatch"] = (
            "SENT"
            if discord_message_id
            else "FAILED"
        )

        return incident

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Unable to process Wazuh alert: "
                f"{exc}"
            ),
        ) from exc


@app.get(
    "/api/v1/incidents/{incident_id}",
    response_model=Incident,
)
async def get_incident(
    incident_id: str,
):

    incident = incident_store.get(
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return incident


@app.get(
    "/api/v1/incidents",
    response_model=list[Incident],
)
async def list_incidents():

    return incident_store.list()
