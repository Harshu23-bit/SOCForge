from __future__ import annotations

import logging

import httpx

from datetime import datetime, timezone
from .config import settings
from .schemas import (
    ActionStatus,
    ActionType,
    Incident,
    IncidentStatus,
)

logger = logging.getLogger("socforge-soar")


SEVERITY_COLORS = {
    "CRITICAL": 0xE74C3C,
    "HIGH": 0xE67E22,
    "MEDIUM": 0xF1C40F,
    "LOW": 0x2ECC71,
    "UNKNOWN": 0x95A5A6,
}


def _code(value: object) -> str:
    """
    Safely format a value for a Discord inline code block.
    """
    if value is None:
        return "N/A"

    text = str(value)

    # Avoid breaking Discord markdown/code formatting.
    text = text.replace("`", "'")

    return f"`{text}`"


def _truncate(
    value: str | None,
    limit: int = 1000,
) -> str:
    if not value:
        return "N/A"

    value = value.replace("`", "'")

    if len(value) <= limit:
        return value

    return value[: limit - 3] + "..."


def _fit_discord_field(
    value: str,
    limit: int = 1000,
) -> str:
    """
    Keep a Discord embed field value safely below
    the 1024-character field-value limit.
    """
    if not value:
        return "N/A"

    if len(value) <= limit:
        return value

    return value[: limit - 3] + "..."


def _format_vt(incident: Incident) -> str:
    enrichment = incident.enrichment

    if enrichment is None:
        return "Not enriched"

    vt = enrichment.virustotal

    if vt.status == "enriched":
        return (
            f"{vt.malicious}/{vt.total_engines} malicious"
        )

    if vt.status == "not_found":
        return "Hash not found"

    if vt.status == "skipped":
        return "Skipped"

    if vt.status == "rate_limited":
        return "Rate limited"

    return vt.status


def _format_mitre(incident: Incident) -> str:
    enrichment = incident.enrichment

    if enrichment is None:
        return "N/A"

    mitre = enrichment.mitre

    if not mitre.technique_id:
        return "No mapping"

    if not mitre.subtechniques:
        return (
            f"{mitre.technique_id} — "
            f"{mitre.technique_name}"
        )

    return "\n".join(
        [
            (
                f"{mitre.technique_id} — "
                f"{mitre.technique_name}"
            ),
            *(
                f"• {item}"
                for item in mitre.subtechniques
            ),
        ]
    )


def _format_process(incident: Incident) -> str:
    process = incident.detection.process

    lines: list[str] = []

    if process.name:
        lines.append(
            f"Name: {_code(process.name)}"
        )

    if process.pid is not None:
        lines.append(
            f"PID: {_code(process.pid)}"
        )

    if process.ppid is not None:
        lines.append(
            f"PPID: {_code(process.ppid)}"
        )

    if process.user:
        lines.append(
            f"User: {_code(process.user)}"
        )

    if process.path:
        lines.append(
            f"Path: {_code(process.path)}"
        )

    if process.command_line:
        lines.append(
            "Command Line:\n"
            f"```text\n"
            f"{_truncate(process.command_line, 900)}\n"
            f"```"
        )

    return "\n".join(lines) or "No process telemetry"


def _format_ai_assessment(
    incident: Incident,
) -> str:
    assessment = incident.ai_assessment

    if assessment is None:
        return "AI assessment unavailable."

    value = (
        f"**Assessment:** "
        f"{_truncate(assessment.threat_assessment, 350)}\n\n"
        f"**Confidence:** "
        f"{assessment.confidence_score}%\n\n"
        f"**Summary:** "
        f"{_truncate(assessment.summary, 350)}"
    )

    return _fit_discord_field(value)


def _format_known_facts(
    incident: Incident,
) -> str:
    assessment = incident.ai_assessment

    if not assessment or not assessment.known_facts:
        return "No AI-confirmed facts available."

    value = "\n".join(
        f"• {_truncate(fact, 350)}"
        for fact in assessment.known_facts[:6]
    )

    return _fit_discord_field(value)


def _format_unknowns(
    incident: Incident,
) -> str:
    assessment = incident.ai_assessment

    if (
        not assessment
        or not assessment.investigative_unknowns
    ):
        return "No investigative gaps reported."

    value = "\n".join(
        f"• {_truncate(item, 350)}"
        for item in assessment.investigative_unknowns[:6]
    )

    return _fit_discord_field(value)


def _format_recommendations(
    incident: Incident,
) -> str:
    actions = (
        incident.triage.recommended_actions
        if incident.triage
        else []
    )

    if not actions:
        return "No recommendations available."

    value = "\n".join(
        f"• {_truncate(action, 300)}"
        for action in actions[:6]
    )

    return _fit_discord_field(value)


def _format_response_history(
    incident: Incident,
) -> str:
    if not incident.action_audit:
        return "No analyst actions recorded."

    lines: list[str] = []

    for audit in incident.action_audit[-6:]:
        status_icon = {
            ActionStatus.REQUESTED: "🟡",
            ActionStatus.EXECUTING: "🔵",
            ActionStatus.SUCCESS: "✅",
            ActionStatus.FAILED: "❌",
            ActionStatus.BLOCKED: "⛔",
        }.get(
            audit.status,
            "⚪",
        )

        completed_time = (
            audit.completed_at
            or audit.requested_at
        )

        lines.append(
            f"{status_icon} **{audit.action.value}**\n"
            f"Analyst: `{audit.analyst_name}`\n"
            f"Status: `{audit.status.value}`\n"
            f"Time: <t:{int(completed_time.timestamp())}:f>\n"
            f"Result: {_truncate(audit.result, 300)}"
        )

    return "\n\n".join(lines)


def validate_discord_embed(
    embed: dict,
) -> None:
    """
    Raise ValueError if an embed violates Discord's
    per-field limits.
    """

    title = embed.get("title", "")
    description = embed.get("description", "")

    if len(title) > 256:
        raise ValueError(
            f"Discord embed title too long: {len(title)}"
        )

    if len(description) > 4096:
        raise ValueError(
            f"Discord embed description too long: "
            f"{len(description)}"
        )

    fields = embed.get("fields", [])

    if len(fields) > 25:
        raise ValueError(
            "Discord embed contains more than 25 fields."
        )

    for index, field in enumerate(fields):
        name = str(field.get("name", ""))
        value = str(field.get("value", ""))

        if len(name) > 256:
            raise ValueError(
                f"Embed field {index} name too long."
            )

        if len(value) > 1024:
            raise ValueError(
                f"Embed field {index} value too long: "
                f"{len(value)}"
            )

    footer = embed.get("footer", {})
    footer_text = str(
        footer.get("text", "")
    )

    if len(footer_text) > 2048:
        raise ValueError(
            "Discord embed footer too long."
        )


def build_incident_embed(
    incident: Incident,
) -> dict:
    """
    Convert the canonical Incident object into a
    professional Discord incident embed.
    """
    received_at = datetime.now(timezone.utc)

    triage = incident.triage
    detection = incident.detection

    severity = (
        triage.severity.value
        if triage
        else detection.severity.value
    )

    risk_score = (
        triage.risk_score
        if triage
        else incident.risk_score
    )

    containment_required = (
        triage.containment_required
        if triage
        else False
    )

    if incident.status == IncidentStatus.DISMISSED:
        status_text = "⚪ DISMISSED"

    elif incident.status == IncidentStatus.CONTAINED:
        status_text = "🟢 CONTAINED"

    elif incident.status == IncidentStatus.RESOLVED:
        status_text = "✅ RESOLVED"

    elif containment_required:
        status_text = "🔴 ACTIVE — CONTAINMENT REQUIRED"

    else:
        status_text = "🟡 INVESTIGATION REQUIRED"

    title = (
        detection.rule_description
        or "Security Alert Detected"
    )

    agent_name = (
        detection.agent.name
        or "Unknown Agent"
    )

    embed = {
        "title": (
            f"🚨 {severity} — {title}"
        ),
        "description": (
            f"**Incident:** {_code(incident.incident_id)}\n"
            f"**Status:** {status_text}"
        ),
        "color": SEVERITY_COLORS.get(
            severity,
            SEVERITY_COLORS["UNKNOWN"],
        ),
        "fields": [
            {
                "name": "Host / Agent",
                "value": _code(agent_name),
                "inline": True,
            },
            {
                "name": "Rule ID",
                "value": _code(
                    detection.rule_id
                ),
                "inline": True,
            },
            {
                "name": "Risk Score",
                "value": _code(
                    f"{risk_score}/100"
                    if risk_score is not None
                    else "N/A"
                ),
                "inline": True,
            },
            {
                "name": "Severity",
                "value": _code(severity),
                "inline": True,
            },
            {
                "name": "VirusTotal",
                "value": _code(
                    _format_vt(incident)
                ),
                "inline": True,
            },
            {
                "name": "Event Time",
                "value": (
                    f"<t:{int(detection.timestamp.timestamp())}:F>"
                    "\n"
                    f"<t:{int(detection.timestamp.timestamp())}:R>"
                ),
                "inline": True,
            },
            {
                "name": "SOCForge Received",
                "value": (
                   f"<t:{int(received_at.timestamp())}:F>"
                    "\n"
                    f"<t:{int(received_at.timestamp())}:R>"
                ),
                "inline": True,
            },
            {
                "name": "Process Execution",
                "value": _format_process(
                    incident
                ),
                "inline": False,
            },
            {
                "name": "Artifact",
                "value": (
                    f"Path: {_code(detection.file_path)}\n"
                    f"SHA-256: {_code(detection.file_hash)}"
                ),
                "inline": False,
            },
            {
                "name": "Network",
                "value": (
                    f"Destination: "
                    f"{_code(detection.dst_ip)}\n"
                    f"Port: "
                    f"{_code(detection.dst_port)}"
                ),
                "inline": True,
            },
            {
                "name": "MITRE ATT&CK",
                "value": _format_mitre(
                    incident
                ),
                "inline": True,
            },
            {
                "name": "🤖 AI Assessment",
                "value": _format_ai_assessment(
                    incident
                ),
                "inline": False,
            },
            {
                "name": "Observed / Confirmed Facts",
                "value": _format_known_facts(
                    incident
                ),
                "inline": False,
            },
            {
                "name": "Investigative Unknowns",
                "value": _format_unknowns(
                    incident
                ),
                "inline": False,
            },
            {
                "name": "Recommended Actions",
                "value": _format_recommendations(
                    incident
                ),
                "inline": False,
            },
            {
                "name": "⚡ Response History",
                "value": _format_response_history(
                    incident
                ),
                "inline": False,
            },
        ],
        "footer": {
            "text": (
                "SOCForge AI SOAR Engine • "
                f"Incident {incident.incident_id}"
            )
        },
        "timestamp": received_at.isoformat(),
    }

    return embed


def build_incident_components(
    incident: Incident,
) -> list[dict]:
    """
    Build Discord action buttons based on current
    incident state.

    Completed/resolved actions are disabled.
    """

    incident_id = incident.incident_id

    isolate_disabled = False
    kill_disabled = False
    dismiss_disabled = False

    for audit in incident.action_audit:

        if audit.action == ActionType.ISOLATE:
            if audit.status in {
                ActionStatus.REQUESTED,
                ActionStatus.EXECUTING,
                ActionStatus.SUCCESS,
            }:
                isolate_disabled = True

        elif audit.action == ActionType.KILL:
            if audit.status in {
                ActionStatus.REQUESTED,
                ActionStatus.EXECUTING,
                ActionStatus.SUCCESS,
            }:
                kill_disabled = True

        elif audit.action == ActionType.DISMISS:
            if audit.status in {
                ActionStatus.REQUESTED,
                ActionStatus.EXECUTING,
                ActionStatus.SUCCESS,
            }:
                dismiss_disabled = True

    # Once dismissed/resolved/contained, don't allow
    # contradictory actions.
    if incident.status in {
        IncidentStatus.DISMISSED,
        IncidentStatus.RESOLVED,
    }:
        isolate_disabled = True
        kill_disabled = True
        dismiss_disabled = True

    return [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 4,
                    "label": "🔒 Isolate Host",
                    "custom_id": (
                        f"incident:{incident_id}:isolate"
                    ),
                    "disabled": isolate_disabled,
                },
                {
                    "type": 2,
                    "style": 2,
                    "label": "🛑 Kill PID",
                    "custom_id": (
                        f"incident:{incident_id}:kill"
                    ),
                    "disabled": kill_disabled,
                },
                {
                    "type": 2,
                    "style": 3,
                    "label": "✖ Dismiss",
                    "custom_id": (
                        f"incident:{incident_id}:dismiss"
                    ),
                    "disabled": dismiss_disabled,
                },
            ],
        }
    ]


async def send_incident_to_discord(
    incident: Incident,
) -> str | None:
    """
    Send a fully rendered incident to Discord.

    Returns the Discord message ID when successful.
    """

    webhook_url = settings.discord_webhook_url

    if not webhook_url:
        logger.warning(
            "Discord webhook URL is not configured."
        )
        return None

    embed = build_incident_embed(incident)

    validate_discord_embed(embed)

    payload = {
        "embeds": [embed],
        "components": build_incident_components(
            incident
        ),
    }

    url = f"{webhook_url}?wait=true"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0)
        ) as client:

            response = await client.post(
                url,
                json=payload,
            )

        if response.status_code not in (
            200,
            201,
        ):
            logger.error(
                "Discord webhook failed: HTTP %s %s",
                response.status_code,
                response.text,
            )
            return None

        data = response.json()

        message_id = data.get("id")

        if not message_id:
            logger.error(
                "Discord webhook response contained "
                "no message ID."
            )
            return None

        logger.info(
            "Discord incident %s posted as message %s",
            incident.incident_id,
            message_id,
        )

        return str(message_id)

    except httpx.HTTPError as exc:
        logger.exception(
            "Discord HTTP request failed: %s",
            exc,
        )
        return None


async def update_incident_message(
    incident: Incident,
    action_status: ActionStatus,
    analyst_name: str,
    result: str,
) -> bool:

    message_id = incident.metadata.get(
        "discord_message_id"
    )

    if not message_id:
        logger.warning(
            "Incident %s has no Discord message ID.",
            incident.incident_id,
        )
        return False

    webhook_url = settings.discord_webhook_url

    if not webhook_url:
        return False

    status_title = (
        "Action Completed"
        if action_status == ActionStatus.SUCCESS
        else "Action Failed"
        if action_status == ActionStatus.FAILED
        else "Action Blocked"
    )

    original_embed = build_incident_embed(
        incident
    )

    original_embed["description"] = (
        original_embed.get(
            "description",
            "",
        )
        + "\n\n"
        f"**Latest Action:** `{status_title}`\n"
        f"**Analyst:** `{analyst_name}`\n"
        f"**Result:** {_truncate(result, 500)}"
    )

    payload = {
        "embeds": [original_embed],
        "components": (
            build_incident_components(incident)
        ),
    }

    url = (
        f"{webhook_url}"
        f"/messages/{message_id}"
    )

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0)
        ) as client:

            response = await client.patch(
                url,
                json=payload,
            )

        if response.status_code not in (
            200,
            204,
        ):
            logger.error(
                "Discord message update failed: "
                "HTTP %s %s",
                response.status_code,
                response.text,
            )
            return False

        return True

    except httpx.HTTPError as exc:
        logger.exception(
            "Discord card update failed: %s",
            exc,
        )
        return False
