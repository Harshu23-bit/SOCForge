from app.enrichment import derive_mitre_mapping
from app.ingestion import normalize_wazuh_alert
from app.schemas import (
    EnrichmentResult,
    VirusTotalResult,
)
from app.triage import (
    calculate_risk_score,
    determine_containment_required,
    triage_event,
)


def build_event():
    alert = {
        "rule": {
            "id": "100201",
            "level": 12,
            "description": "Suspicious PowerShell execution",
        },
        "agent": {
            "id": "001",
            "name": "SOC-WIN01",
        },
        "process": {
            "pid": 6840,
            "name": "powershell.exe",
            "command_line": (
                "powershell.exe "
                "-EncodedCommand TEST"
            ),
        },
        "data": {
            "dstip": "8.8.8.8",
        },
    }

    return normalize_wazuh_alert(alert)


def build_enrichment(event):
    return EnrichmentResult(
        virustotal=VirusTotalResult(
            status="enriched",
            file_hash="abc123",
            malicious=20,
            suspicious=2,
            total_engines=70,
        ),
        mitre=derive_mitre_mapping(event),
    )


def test_risk_score_is_deterministic():
    event = build_event()
    enrichment = build_enrichment(event)

    score, reasons = calculate_risk_score(
        event,
        enrichment,
    )

    assert score == 100
    assert len(reasons) >= 3


def test_critical_requires_containment():
    event = build_event()
    enrichment = build_enrichment(event)

    result = triage_event(
        event,
        enrichment,
    )

    assert result.risk_score == 100
    assert result.severity.value == "CRITICAL"
    assert result.containment_required is True


def test_recommendations_are_generated():
    event = build_event()
    enrichment = build_enrichment(event)

    result = triage_event(
        event,
        enrichment,
    )

    assert len(
        result.recommended_actions
    ) > 0

    assert any(
        action.startswith("[P0]")
        for action in result.recommended_actions
    )
