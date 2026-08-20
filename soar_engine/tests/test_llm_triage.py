from unittest.mock import patch

import pytest

from app.enrichment import enrich_detection
from app.incident import IncidentStore
from app.ingestion import normalize_wazuh_alert
from app.llm_triage import (
    build_ai_prompt,
    generate_ai_assessment,
)
from app.schemas import (
    AIAssessment,
    EnrichmentResult,
    MitreMapping,
    TriageResult,
    VirusTotalResult,
)

from app.triage import triage_event


def build_incident():
    alert = {
        "timestamp": (
            "2026-08-17T02:30:00+05:30"
        ),
        "rule": {
            "id": "100201",
            "level": 12,
            "description": (
                "Suspicious PowerShell execution"
            ),
        },
        "agent": {
            "id": "001",
            "name": "SOC-WIN01",
            "ip": "192.168.1.25",
        },
        "process": {
            "pid": 6840,
            "ppid": 1200,
            "name": "powershell.exe",
            "executable": (
                "C:\\Windows\\System32\\"
                "WindowsPowerShell\\v1.0\\"
                "powershell.exe"
            ),
            "command_line": (
                "powershell.exe "
                "-ExecutionPolicy Bypass "
                "-EncodedCommand TEST"
            ),
            "user": "CORP\\analyst",
        },
    }

    return normalize_wazuh_alert(alert)


@pytest.mark.asyncio
async def test_ai_fallback_without_api_key():

    event = build_incident()

    with patch(
        "app.llm_triage.settings"
    ) as mock_settings:

        mock_settings.gemini_api_key = ""

        enrichment = await enrich_detection(
            event
        )

        triage = triage_event(
            event,
            enrichment,
        )

        store = IncidentStore()

        incident = store.create(
            detection=event,
            enrichment=enrichment,
            triage=triage,
        )

        assessment = await generate_ai_assessment(
            incident
        )

        assert isinstance(
            assessment,
            AIAssessment,
        )

        assert assessment.confidence_score == 0
        assert assessment.model == (
            "gemini-3.6-flash"
        )


def test_ai_prompt_contains_evidence():

    event = build_incident()

    store = IncidentStore()

    enrichment = EnrichmentResult(
        virustotal=VirusTotalResult(
            status="enriched",
            file_hash="test-sha256",
            malicious=65,
            suspicious=0,
            harmless=0,
            undetected=2,
            total_engines=67,
            reputation=3789,
            meaningful_name="test-sample",
            type_description="PowerShell",
        ),
        mitre=MitreMapping(
            tactic="Execution",
            technique_id="T1059",
            technique_name=(
                "Command and Scripting Interpreter"
            ),
            subtechniques=[
                "T1059.001 — PowerShell"
            ],
            observed_processes=[
                "powershell.exe"
            ],
            observed_indicators=[
                "Encoded PowerShell command line"
            ],
            evidence=(
                "Observed process: powershell.exe | "
                "Observed indicators: "
                "Encoded PowerShell command line"
            ),
        ),
    )

    triage = TriageResult(
        risk_score=100,
        severity="CRITICAL",
        containment_required=True,
        reasons=[
            "Wazuh rule level: 12",
            "Encoded command-line indicator observed.",
        ],
        recommended_actions=[
            "[P0] Isolate host SOC-WIN01",
            "[P1] Investigate or terminate PID 6840",
        ],
    )

    incident = store.create(
        detection=event,
        enrichment=enrichment,
        triage=triage,
    )

    prompt = build_ai_prompt(
        incident
    )

    assert "powershell.exe" in prompt
    assert "-EncodedCommand" in prompt
    assert "100201" in prompt
    assert "SOC-WIN01" in prompt
