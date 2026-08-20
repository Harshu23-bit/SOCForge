from unittest.mock import AsyncMock, patch

import pytest

from app.enrichment import (
    derive_mitre_mapping,
    enrich_detection,
    get_virustotal_hash_report,
)
from app.ingestion import normalize_wazuh_alert
from app.schemas import VirusTotalResult


@pytest.fixture
def powershell_event():
    alert = {
        "timestamp": "2026-08-17T02:15:30+05:30",
        "rule": {
            "id": "100201",
            "level": 12,
            "description": "Suspicious PowerShell execution",
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
                "-ExecutionPolicy Bypass "
                "-EncodedCommand TEST"
            ),
        },
    }

    return normalize_wazuh_alert(alert)


def test_mitre_maps_powershell(powershell_event):
    result = derive_mitre_mapping(
        powershell_event
    )

    assert result.tactic == "Execution"
    assert result.technique_id == "T1059"
    assert (
        "T1059.001 — PowerShell"
        in result.subtechniques
    )


@pytest.mark.asyncio
async def test_vt_skips_without_hash():
    result = await get_virustotal_hash_report(
        None
    )

    assert result.status == "skipped"
    assert result.file_hash is None


@pytest.mark.asyncio
async def test_enrichment_without_hash(
    powershell_event,
):
    with patch(
        "app.enrichment.get_virustotal_hash_report",
        new=AsyncMock(
            return_value=VirusTotalResult(
                status="skipped",
                error="No file hash available.",
            )
        ),
    ):

        result = await enrich_detection(
            powershell_event
        )

        assert result.virustotal.status == "skipped"
        assert result.mitre.tactic == "Execution"


@pytest.mark.asyncio
async def test_enrichment_does_not_require_vt(
    powershell_event,
):
    with patch(
        "app.enrichment.get_virustotal_hash_report",
        new=AsyncMock(
            return_value=VirusTotalResult(
                status="not_found",
                file_hash=None,
            )
        ),
    ):

        result = await enrich_detection(
            powershell_event
        )

        assert result.virustotal.status == "not_found"
        assert result.mitre.technique_id == "T1059"
