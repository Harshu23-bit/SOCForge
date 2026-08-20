from __future__ import annotations

import logging
from typing import Any

import httpx

from .config import settings
from .schemas import (
    DetectionEvent,
    EnrichmentResult,
    MitreMapping,
    VirusTotalResult,
)

logger = logging.getLogger("socforge-soar")


MITRE_SUBTECHNIQUES: dict[str, tuple[str, str]] = {
    "powershell.exe": (
        "T1059.001",
        "PowerShell",
    ),
    "pwsh": (
        "T1059.001",
        "PowerShell",
    ),
    "cmd.exe": (
        "T1059.003",
        "Windows Command Shell",
    ),
    "bash": (
        "T1059.004",
        "Unix Shell",
    ),
    "sh": (
        "T1059.004",
        "Unix Shell",
    ),
    "zsh": (
        "T1059.004",
        "Unix Shell",
    ),
    "wscript.exe": (
        "T1059.005",
        "Visual Basic",
    ),
    "cscript.exe": (
        "T1059.005",
        "Visual Basic",
    ),
    "python.exe": (
        "T1059.006",
        "Python",
    ),
    "python": (
        "T1059.006",
        "Python",
    ),
    "python3": (
        "T1059.006",
        "Python",
    ),
}


def _process_basename(value: str | None) -> str | None:
    if not value:
        return None

    normalized = value.replace("\\", "/")

    return normalized.rsplit("/", 1)[-1].lower()


def _get_parent_process_name(event: DetectionEvent) -> str | None:
    raw = event.raw_alert

    candidates = [
        raw.get("process", {}).get("parent", {}).get("name"),
        raw.get("process", {}).get("parent_name"),
        raw.get("data", {}).get("parent_process_name"),
        raw.get("data", {}).get("parent_process"),
        raw.get("data", {}).get("win", {})
        .get("eventdata", {})
        .get("parentImage"),
        raw.get("data", {}).get("audit", {}).get("parent_name"),
    ]

    for candidate in candidates:
        if candidate:
            return str(candidate)

    return None


def derive_mitre_mapping(
    event: DetectionEvent,
) -> MitreMapping:
    """
    Map observed process telemetry to ATT&CK.

    Important:
    - observed_* fields contain facts actually present in telemetry
    - ATT&CK fields contain SOCForge's deterministic mapping
    """

    observed_processes: list[str] = []
    observed_indicators: list[str] = []
    mapped_subtechniques: list[str] = []

    parent = _get_parent_process_name(event)

    process_candidates = [
        parent,
        event.process.name,
        event.process.path,
    ]

    for value in process_candidates:
        clean = _process_basename(value)

        if clean and clean not in observed_processes:
            observed_processes.append(clean)

    # Observe the actual command line.
    command_line = event.process.command_line

    if command_line:
        normalized_command = command_line.lower()

        if (
            "-encodedcommand" in normalized_command
            or "-enc " in normalized_command
        ):
            observed_indicators.append(
                "Encoded PowerShell command line"
            )

    # Deterministic ATT&CK mapping.
    for process_name in observed_processes:
        mapping = MITRE_SUBTECHNIQUES.get(
            process_name
        )

        if mapping is None:
            continue

        technique_id, technique_name = mapping

        formatted = (
            f"{technique_id} — {technique_name}"
        )

        if formatted not in mapped_subtechniques:
            mapped_subtechniques.append(
                formatted
            )

    if mapped_subtechniques:
        evidence_parts = []

        if observed_processes:
            evidence_parts.append(
                "Observed process: "
                + ", ".join(observed_processes)
            )

        if observed_indicators:
            evidence_parts.append(
                "Observed indicators: "
                + ", ".join(observed_indicators)
            )

        return MitreMapping(
            tactic="Execution",
            technique_id="T1059",
            technique_name=(
                "Command and Scripting Interpreter"
            ),
            subtechniques=mapped_subtechniques,
            observed_processes=observed_processes,
            observed_indicators=observed_indicators,
            evidence=" | ".join(evidence_parts),
        )

    return MitreMapping(
        tactic="Unknown",
        technique_id=None,
        technique_name=None,
        subtechniques=[],
        observed_processes=observed_processes,
        observed_indicators=observed_indicators,
        evidence=(
            "No supported ATT&CK mapping was "
            "derived from observed telemetry."
        ),
    )


async def get_virustotal_hash_report(
    file_hash: str | None,
) -> VirusTotalResult:
    """
    Query VirusTotal using an observed file hash.

    No fabricated values are returned.
    """

    if not file_hash:
        return VirusTotalResult(
            status="skipped",
            error="No file hash available.",
        )

    if not settings.virustotal_api_key:
        logger.warning(
            "VirusTotal API key is not configured."
        )

        return VirusTotalResult(
            status="skipped",
            file_hash=file_hash,
            error="API key not configured.",
        )

    url = (
        "https://www.virustotal.com/api/v3/files/"
        f"{file_hash}"
    )

    headers = {
        "x-apikey": settings.virustotal_api_key,
    }

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0)
        ) as client:

            response = await client.get(
                url,
                headers=headers,
            )

    except httpx.TimeoutException:
        logger.warning(
            "VirusTotal request timed out."
        )

        return VirusTotalResult(
            status="error",
            file_hash=file_hash,
            error="VirusTotal request timed out.",
        )

    except httpx.HTTPError as exc:
        logger.error(
            "VirusTotal HTTP error: %s",
            exc,
        )

        return VirusTotalResult(
            status="error",
            file_hash=file_hash,
            error="VirusTotal HTTP request failed.",
        )

    if response.status_code == 404:
        return VirusTotalResult(
            status="not_found",
            file_hash=file_hash,
            error="Hash not found on VirusTotal.",
        )

    if response.status_code == 429:
        logger.warning(
            "VirusTotal rate limit reached."
        )

        return VirusTotalResult(
            status="rate_limited",
            file_hash=file_hash,
            error="VirusTotal rate limit reached.",
        )

    if response.status_code != 200:
        logger.error(
            "VirusTotal API returned HTTP %s.",
            response.status_code,
        )

        return VirusTotalResult(
            status="error",
            file_hash=file_hash,
            error=(
                "VirusTotal returned HTTP "
                f"{response.status_code}."
            ),
        )

    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        return VirusTotalResult(
            status="error",
            file_hash=file_hash,
            error="VirusTotal returned invalid JSON.",
        )

    attributes = (
        payload
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    total = sum(
        int(value)
        for value in stats.values()
        if isinstance(value, int)
    )

    return VirusTotalResult(
        status="enriched",
        file_hash=file_hash,
        malicious=int(
            stats.get("malicious", 0)
        ),
        suspicious=int(
            stats.get("suspicious", 0)
        ),
        harmless=int(
            stats.get("harmless", 0)
        ),
        undetected=int(
            stats.get("undetected", 0)
        ),
        total_engines=total,
        reputation=attributes.get("reputation"),
        meaningful_name=attributes.get(
            "meaningful_name"
        ),
        type_description=attributes.get(
            "type_description"
        ),
    )


async def enrich_detection(
    event: DetectionEvent,
) -> EnrichmentResult:
    """
    Run all Stage-2 enrichment against a normalized event.
    """

    virustotal = await get_virustotal_hash_report(
        event.file_hash
    )

    mitre = derive_mitre_mapping(event)

    return EnrichmentResult(
        virustotal=virustotal,
        mitre=mitre,
    )
