from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import (
    AIAssessment,
    EnrichmentResult,
    MitreMapping,
    TriageResult,
    VirusTotalResult,
)


client = TestClient(app)


def mock_enrichment():
    return EnrichmentResult(
        virustotal=VirusTotalResult(
            status="skipped",
            error="Mocked during API test.",
        ),
        mitre=MitreMapping(
            tactic="Execution",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            subtechniques=[
                "T1059.001 — PowerShell",
            ],
            observed_processes=[
                "powershell.exe",
            ],
            observed_indicators=[
                "Encoded PowerShell command line",
            ],
            evidence=(
                "Mocked enrichment for API test."
            ),
        ),
    )


def mock_ai_assessment():
    return AIAssessment(
        operational_title=(
            "Test Suspicious PowerShell Execution"
        ),
        summary=(
            "Mocked AI assessment for API testing."
        ),
        confidence_score=95,
        threat_assessment=(
            "Mocked threat assessment."
        ),
        known_facts=[
            "Mocked fact 1",
            "Mocked fact 2",
        ],
        investigative_unknowns=[
            "Mocked unknown 1",
        ],
        analyst_recommendation=(
            "[P0] Investigate the test incident."
        ),
        model="gemini-3.6-flash",
    )


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "SOCForge SOAR Engine"


@patch(
    "app.main.send_incident_to_discord",
    new_callable=AsyncMock,
)
@patch(
    "app.main.generate_ai_assessment",
    new_callable=AsyncMock,
)
@patch(
    "app.main.enrich_detection",
    new_callable=AsyncMock,
)
def test_wazuh_event_creates_incident(
    mock_enrich,
    mock_ai,
    mock_discord,
):
    mock_enrich.return_value = mock_enrichment()
    mock_ai.return_value = mock_ai_assessment()
    mock_discord.return_value = "TEST-DISCORD-MESSAGE-ID"

    alert = {
        "timestamp": "2026-08-17T02:15:30+05:30",
        "rule": {
            "id": "100201",
            "level": 12,
            "description": (
                "Suspicious process execution detected"
            ),
        },
        "agent": {
            "id": "001",
            "name": "SOC-WIN01",
            "ip": "192.168.1.25",
        },
        "process": {
            "pid": 6840,
            "name": "powershell.exe",
            "command_line": (
                "powershell.exe "
                "-EncodedCommand TEST"
            ),
        },
    }

    response = client.post(
        "/api/v1/events/wazuh",
        json=alert,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"].startswith("INC-")
    assert data["status"] == "NEW"

    assert data["detection"]["rule_id"] == "100201"
    assert data["detection"]["severity"] == "HIGH"

    assert (
        data["detection"]["agent"]["name"]
        == "SOC-WIN01"
    )

    assert (
        data["detection"]["process"]["pid"]
        == 6840
    )

    assert (
        data["ai_assessment"]["model"]
        == "gemini-3.6-flash"
    )

    assert (
        data["metadata"]["discord_message_id"]
        == "TEST-DISCORD-MESSAGE-ID"
    )

    mock_enrich.assert_awaited_once()
    mock_ai.assert_awaited_once()
    mock_discord.assert_awaited_once()


@patch(
    "app.main.send_incident_to_discord",
    new_callable=AsyncMock,
)
@patch(
    "app.main.generate_ai_assessment",
    new_callable=AsyncMock,
)
@patch(
    "app.main.enrich_detection",
    new_callable=AsyncMock,
)
def test_get_incident(
    mock_enrich,
    mock_ai,
    mock_discord,
):
    mock_enrich.return_value = mock_enrichment()
    mock_ai.return_value = mock_ai_assessment()
    mock_discord.return_value = "TEST-DISCORD-MESSAGE-ID"

    alert = {
        "rule": {
            "id": "100300",
            "level": 8,
            "description": "Incident retrieval test",
        }
    }

    create_response = client.post(
        "/api/v1/events/wazuh",
        json=alert,
    )

    assert create_response.status_code == 200

    incident_id = create_response.json()[
        "incident_id"
    ]

    response = client.get(
        f"/api/v1/incidents/{incident_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["incident_id"] == incident_id
    assert (
        data["detection"]["rule_id"]
        == "100300"
    )

    assert data["ai_assessment"] is not None


def test_unknown_incident_returns_404():
    response = client.get(
        "/api/v1/incidents/INC-DOESNOTEXIST"
    )

    assert response.status_code == 404
