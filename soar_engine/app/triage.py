from __future__ import annotations

import logging

from .schemas import (
    DetectionEvent,
    EnrichmentResult,
    Severity,
    TriageResult,
)

logger = logging.getLogger("socforge-soar")


def _base_score_from_rule_level(
    level: int | None,
) -> int:

    if level is None:
        return 0

    if level >= 15:
        return 80

    if level >= 12:
        return 65

    if level >= 10:
        return 50

    if level >= 7:
        return 35

    if level >= 4:
        return 20

    if level >= 1:
        return 10

    return 0


def _severity_from_score(
    score: int,
) -> Severity:

    if score >= 85:
        return Severity.CRITICAL

    if score >= 65:
        return Severity.HIGH

    if score >= 40:
        return Severity.MEDIUM

    if score > 0:
        return Severity.LOW

    return Severity.UNKNOWN


def _is_encoded_command(
    command_line: str | None,
) -> bool:

    if not command_line:
        return False

    normalized = command_line.lower()

    indicators = (
        "-encodedcommand",
        "-enc ",
        "frombase64string",
        "base64",
    )

    return any(
        indicator in normalized
        for indicator in indicators
    )


def _is_scripting_interpreter(
    process_name: str | None,
) -> bool:

    if not process_name:
        return False

    normalized = process_name.lower()

    return normalized in {
        "powershell.exe",
        "pwsh",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "bash",
        "sh",
        "zsh",
        "python",
        "python3",
        "python.exe",
    }


def calculate_risk_score(
    event: DetectionEvent,
    enrichment: EnrichmentResult,
) -> tuple[int, list[str]]:

    score = _base_score_from_rule_level(
        event.rule_level
    )

    reasons: list[str] = []

    if event.rule_level is not None:
        reasons.append(
            f"Wazuh rule level: {event.rule_level}"
        )

    vt = enrichment.virustotal

    if vt.status == "enriched":
        if vt.malicious > 0:
            vt_bonus = min(
                20,
                vt.malicious,
            )

            score += vt_bonus

            reasons.append(
                "VirusTotal reported "
                f"{vt.malicious}/{vt.total_engines} "
                "malicious detections."
            )

        elif vt.suspicious > 0:
            score += min(
                10,
                vt.suspicious * 2,
            )

            reasons.append(
                "VirusTotal reported suspicious "
                f"verdicts: {vt.suspicious}."
            )

    if _is_scripting_interpreter(
        event.process.name
    ):
        score += 5

        reasons.append(
            f"Script interpreter observed: "
            f"{event.process.name}."
        )

    if _is_encoded_command(
        event.process.command_line
    ):
        score += 10

        reasons.append(
            "Encoded command-line indicator observed."
        )

    if event.dst_ip:
        score += 5

        reasons.append(
            f"Outbound destination observed: "
            f"{event.dst_ip}."
        )

    score = min(
        100,
        max(0, score),
    )

    return score, reasons


def determine_containment_required(
    severity: Severity,
    event: DetectionEvent,
    enrichment: EnrichmentResult,
) -> bool:

    if severity == Severity.CRITICAL:
        return True

    if (
        enrichment.virustotal.status == "enriched"
        and enrichment.virustotal.malicious > 0
        and event.process.pid is not None
    ):
        return True

    return False


def generate_recommended_actions(
    severity: Severity,
    containment_required: bool,
    event: DetectionEvent,
) -> list[str]:

    actions: list[str] = []

    if containment_required:
        if event.agent.name:
            actions.append(
                f"[P0] Isolate host "
                f"{event.agent.name}"
            )

        if event.process.pid is not None:
            actions.append(
                f"[P1] Investigate or terminate "
                f"PID {event.process.pid}"
            )

    if event.file_path:
        actions.append(
            f"[P1] Investigate artifact "
            f"{event.file_path}"
        )

    if event.process.command_line:
        actions.append(
            "[P2] Review process command line "
            "and execution origin"
        )

    if event.dst_ip:
        actions.append(
            f"[P2] Investigate network activity "
            f"to {event.dst_ip}"
        )

    if not actions:
        actions.append(
            "[P2] Investigate alert context and "
            "collect supporting telemetry"
        )

    return actions[:4]


def triage_event(
    event: DetectionEvent,
    enrichment: EnrichmentResult,
) -> TriageResult:

    score, reasons = calculate_risk_score(
        event,
        enrichment,
    )

    severity = _severity_from_score(score)

    containment_required = (
        determine_containment_required(
            severity,
            event,
            enrichment,
        )
    )

    actions = generate_recommended_actions(
        severity,
        containment_required,
        event,
    )

    return TriageResult(
        risk_score=score,
        severity=severity,
        containment_required=containment_required,
        reasons=reasons,
        recommended_actions=actions,
    )
