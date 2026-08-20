from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .schemas import (
    AgentInfo,
    DetectionEvent,
    ProcessInfo,
    Severity,
)


def _first(data: dict[str, Any], *paths: str) -> Any:
    """
    Return the first non-empty value from dotted dictionary paths.
    """

    for path in paths:
        current: Any = data

        try:
            for key in path.split("."):
                if not isinstance(current, dict):
                    current = None
                    break

                current = current.get(key)

            if current not in (None, ""):
                return current

        except (AttributeError, TypeError):
            continue

    return None


def _parse_timestamp(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value

    if isinstance(value, str):
        normalized = value.strip()

        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(normalized)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed

        except ValueError:
            pass

    return datetime.now(timezone.utc)


def _severity_from_rule_level(level: Any) -> Severity:
    if level is None:
        return Severity.UNKNOWN

    try:
        level = int(level)
    except (TypeError, ValueError):
        return Severity.UNKNOWN

    if level >= 14:
        return Severity.CRITICAL

    if level >= 10:
        return Severity.HIGH

    if level >= 7:
        return Severity.MEDIUM

    if level >= 1:
        return Severity.LOW

    return Severity.UNKNOWN


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def generate_event_id(alert: dict[str, Any]) -> str:
    """
    Generate a deterministic ID when Wazuh does not provide one.

    This prevents us from inventing security data while still giving
    every event a stable identifier.
    """

    preferred = _first(
        alert,
        "id",
        "event.id",
        "alert.id",
    )

    if preferred:
        return str(preferred)

    canonical = json.dumps(
        alert,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(canonical.encode()).hexdigest()

    return f"wazuh-{digest[:16]}"


def normalize_wazuh_alert(alert: dict[str, Any]) -> DetectionEvent:
    rule_id = _first(
        alert,
        "rule.id",
        "rule_id",
    )

    rule_description = _first(
        alert,
        "rule.description",
        "rule.comment",
        "description",
    )

    rule_level = _safe_int(
        _first(
            alert,
            "rule.level",
            "rule_level",
        )
    )

    agent = AgentInfo(
        id=_string(
            _first(
                alert,
                "agent.id",
                "agent_id",
            )
        ),
        name=_string(
            _first(
                alert,
                "agent.name",
                "agent_name",
            )
        ),
        ip=_string(
            _first(
                alert,
                "agent.ip",
                "agent_ip",
            )
        ),
        os=_string(
            _first(
                alert,
                "agent.os.name",
                "agent.os",
            )
        ),
    )

    process = ProcessInfo(
        pid=_safe_int(
            _first(
                alert,
                "syscheck.process.pid",
                "process.pid",
                "win.eventdata.processId",
                "process_id",
            )
        ),
        ppid=_safe_int(
            _first(
                alert,
                "syscheck.process.ppid",
                "process.ppid",
                "win.eventdata.parentProcessId",
                "parent_process_id",
            )
        ),
        name=_string(
            _first(
                alert,
                "process.name",
                "win.eventdata.image",
            )
        ),
        path=_string(
            _first(
                alert,
                "process.executable",
                "process.path",
                "win.eventdata.image",
            )
        ),
        command_line=_string(
            _first(
                alert,
                "process.command_line",
                "win.eventdata.commandLine",
            )
        ),
        user=_string(
            _first(
                alert,
                "process.user",
                "user.name",
                "win.eventdata.user",
            )
        ),
        cwd=_string(
            _first(
                alert,
                "process.cwd",
                "working_directory",
            )
        ),
    )

    return DetectionEvent(
        event_id=generate_event_id(alert),
        timestamp=_parse_timestamp(
            _first(
                alert,
                "timestamp",
                "@timestamp",
                "event.created",
            )
        ),
        rule_id=_string(rule_id),
        rule_description=_string(rule_description),
        rule_level=rule_level,
        severity=_severity_from_rule_level(rule_level),
        agent=agent,
        process=process,
        src_ip=_string(
            _first(
                alert,
                "data.srcip",
                "srcip",
                "source.ip",
            )
        ),
        dst_ip=_string(
            _first(
                alert,
                "data.dstip",
                "dstip",
                "destination.ip",
            )
        ),
        src_port=_safe_int(
            _first(
                alert,
                "data.srcport",
                "srcport",
                "source.port",
            )
        ),
        dst_port=_safe_int(
            _first(
                alert,
                "data.dstport",
                "dstport",
                "destination.port",
            )
        ),
        file_path=_string(
            _first(
                alert,
                "syscheck.path",
                "file.path",
                "data.path",
            )
        ),
        file_hash=_string(
            _first(
                alert,
                "syscheck.sha256_after",
                "syscheck.sha256",
                "file.hash.sha256",
            )
        ),
        username=_string(
            _first(
                alert,
                "data.dstuser",
                "data.srcuser",
                "user.name",
            )
        ),
        decoder=_string(
            _first(
                alert,
                "decoder.name",
                "decoder",
            )
        ),
        location=_string(
            _first(
                alert,
                "location",
            )
        ),
        full_log=_string(
            _first(
                alert,
                "full_log",
                "full_log.original",
            )
        ),
        raw_alert=alert,
    )


def _string(value: Any) -> str | None:
    if value in (None, ""):
        return None

    return str(value)
