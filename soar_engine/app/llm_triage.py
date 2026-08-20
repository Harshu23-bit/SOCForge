from __future__ import annotations

import logging

from google import genai
from google.genai import types, errors

from .config import settings
from .schemas import (
    AIAssessment,
    Incident,
)

logger = logging.getLogger("socforge-soar")


MODEL_NAME = "gemini-3.6-flash"


def build_ai_prompt(
    incident: Incident,
) -> str:
    detection = incident.detection
    enrichment = incident.enrichment
    triage = incident.triage

    return f"""
You are the SOCForge AI Assessment Engine.

Your task is to analyze a security incident using ONLY
the evidence supplied below.

CRITICAL RULES:

1. Do not invent telemetry.
2. Do not invent process IDs.
3. Do not invent hashes.
4. Do not invent IP addresses.
5. Do not invent timestamps.
6. Do not change the authoritative risk score.
7. Do not change the authoritative severity.
8. Do not claim an ATT&CK technique was observed directly.
   ATT&CK mappings are deterministic SOCForge mappings.
9. Clearly distinguish observed facts from analytical conclusions.
10. If evidence is missing, explicitly say that it is unknown.

AUTHORITATIVE INCIDENT DATA

Incident ID:
{incident.incident_id}

Rule ID:
{detection.rule_id}

Rule Description:
{detection.rule_description}

Rule Level:
{detection.rule_level}

Agent:
{detection.agent.model_dump_json()}

Process:
{detection.process.model_dump_json()}

Source IP:
{detection.src_ip}

Destination IP:
{detection.dst_ip}

Destination Port:
{detection.dst_port}

File Path:
{detection.file_path}

File Hash:
{detection.file_hash}

Username:
{detection.username}

Decoder:
{detection.decoder}

Location:
{detection.location}

Timestamp:
{detection.timestamp.isoformat()}

ENRICHMENT

VirusTotal:
{
    enrichment.virustotal.model_dump_json()
    if enrichment
    else "No enrichment available"
}

MITRE:
{
    enrichment.mitre.model_dump_json()
    if enrichment
    else "No MITRE enrichment available"
}

DETERMINISTIC TRIAGE

{
    triage.model_dump_json()
    if triage
    else "No deterministic triage available"
}

Return an operational SOC assessment.

The operational title must describe the actual alert
without inventing facts.

Known facts must contain only telemetry/enrichment
facts explicitly present above.

Investigative unknowns should identify gaps such as:

- authorization status
- parent process origin
- command-and-control confirmation
- lateral movement status

Do not state those as facts.

The recommendation should be appropriate to the deterministic
severity and containment decision.
"""


async def generate_ai_assessment(
    incident: Incident,
) -> AIAssessment:
    """
    Generate a structured AI assessment.

    Gemini provides interpretation only.
    Deterministic SOCForge triage remains authoritative.
    """

    if not settings.gemini_api_key:
        logger.warning(
            "Gemini API key is not configured."
        )

        return AIAssessment(
            operational_title=(
                "AI Assessment Unavailable"
            ),
            summary=(
                "Gemini assessment was skipped because "
                "the API key is not configured."
            ),
            confidence_score=0,
            threat_assessment=(
                "AI assessment unavailable."
            ),
            known_facts=[],
            investigative_unknowns=[
                "AI assessment unavailable"
            ],
            analyst_recommendation=(
                "Use deterministic SOCForge triage."
            ),
            model=MODEL_NAME,
        )

    try:
        client = genai.Client(
            api_key=settings.gemini_api_key
        )

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=build_ai_prompt(incident),
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AIAssessment,
                automatic_function_calling=types.AutomaticFunctionCallingConfig(
                    disable=True
                ),
            ),
        )

        assessment = AIAssessment.model_validate_json(
            response.text
        )
        assessment.model = MODEL_NAME
        return assessment

    except errors.ServerError as exc:
        logger.warning(
            "Gemini temporarily unavailable: %s",
            exc,
        )

        return AIAssessment(
            operational_title="AI Assessment Temporarily Unavailable",
            summary=(
                "Gemini was temporarily unavailable. "
                "Deterministic SOCForge triage remains authoritative."
            ),
            confidence_score=0,
            threat_assessment=(
                "AI assessment unavailable due to temporary "
                "Gemini service unavailability."
            ),
            known_facts=[],
            investigative_unknowns=[
                "AI assessment unavailable",
            ],
            analyst_recommendation=(
                "Continue with deterministic triage and "
                "manual investigation."
            ),
            model=MODEL_NAME,
        )

    except Exception as exc:
        logger.exception(
            "Gemini assessment failed."
        )

        return AIAssessment(
            operational_title=(
                "AI Assessment Error"
            ),
            summary=(
                "Gemini assessment failed. "
                "Deterministic triage remains authoritative."
            ),
            confidence_score=0,
            threat_assessment=(
                "AI assessment unavailable."
            ),
            known_facts=[],
            investigative_unknowns=[
                "AI assessment failed"
            ],
            analyst_recommendation=(
                "Continue using deterministic triage "
                "and investigate manually."
            ),
            model=MODEL_NAME,
        )
