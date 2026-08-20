from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class DetectionSource(str, Enum):
    WAZUH = "wazuh"


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    user: str | None = None
    cwd: str | None = None


class AgentInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | None = None
    name: str | None = None
    ip: str | None = None
    os: str | None = None


class DetectionEvent(BaseModel):
    """
    Normalized representation of a security event.

    This model deliberately separates normalized fields from
    the original Wazuh payload.
    """

    model_config = ConfigDict(extra="allow")

    event_id: str
    source: DetectionSource = DetectionSource.WAZUH

    timestamp: datetime = Field(default_factory=utc_now)

    rule_id: str | None = None
    rule_description: str | None = None
    rule_level: int | None = None

    severity: Severity = Severity.UNKNOWN

    agent: AgentInfo = Field(default_factory=AgentInfo)

    process: ProcessInfo = Field(default_factory=ProcessInfo)

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None

    file_path: str | None = None
    file_hash: str | None = None

    username: str | None = None

    decoder: str | None = None
    location: str | None = None

    full_log: str | None = None

    raw_alert: dict[str, Any] = Field(default_factory=dict)


class VirusTotalResult(BaseModel):
    status: str = "skipped"

    file_hash: str | None = None

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0

    reputation: int | None = None
    meaningful_name: str | None = None
    type_description: str | None = None

    error: str | None = None


class MitreMapping(BaseModel):
    tactic: str = "Unknown"
    technique_id: str | None = None
    technique_name: str | None = None

    subtechniques: list[str] = Field(default_factory=list)

    observed_processes: list[str] = Field(default_factory=list)
    observed_indicators: list[str] = Field(default_factory=list)

    evidence: str | None = None


class EnrichmentResult(BaseModel):
    virustotal: VirusTotalResult = Field(
        default_factory=VirusTotalResult
    )

    mitre: MitreMapping = Field(
        default_factory=MitreMapping
    )

    enriched_at: datetime = Field(default_factory=utc_now)


class TriageResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    severity: Severity

    containment_required: bool = False

    reasons: list[str] = Field(default_factory=list)

    recommended_actions: list[str] = Field(
        default_factory=list
    )


class AIAssessment(BaseModel):
    operational_title: str

    summary: str

    confidence_score: int = Field(
        ge=0,
        le=100,
    )

    threat_assessment: str

    known_facts: list[str] = Field(
        default_factory=list
    )

    investigative_unknowns: list[str] = Field(
        default_factory=list
    )

    analyst_recommendation: str

    model: str


class ActionType(str, Enum):
    ISOLATE = "ISOLATE"
    KILL = "KILL"
    DISMISS = "DISMISS"


class ActionStatus(str, Enum):
    REQUESTED = "REQUESTED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ActionAudit(BaseModel):
    action_id: str

    incident_id: str
    action: ActionType
    status: ActionStatus

    analyst_id: str
    analyst_name: str

    requested_at: datetime = Field(
        default_factory=utc_now
    )

    completed_at: datetime | None = None

    target_agent: str | None = None
    target_pid: int | None = None

    result: str | None = None


class Incident(BaseModel):
    """
    SOCForge's canonical incident object.

    Everything downstream operates on this object.
    """

    model_config = ConfigDict(extra="allow")

    incident_id: str

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    status: IncidentStatus = IncidentStatus.NEW

    detection: DetectionEvent

    enrichment: EnrichmentResult | None = None

    triage: TriageResult | None = None

    risk_score: int | None = None

    tags: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)

    ai_assessment: AIAssessment | None = None

    action_audit: list[ActionAudit] = Field(
        default_factory=list
    )

    risk_score: int | None = None

    tags: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)
