from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from .schemas import (
    AIAssessment,
    ActionAudit,
    ActionStatus,
    ActionType,
    DetectionEvent,
    EnrichmentResult,
    Incident,
    IncidentStatus,
    TriageResult,
)


class IncidentStore:
    """
    Temporary in-memory incident store.

    This will later be replaced with persistent storage.
    """

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._lock = RLock()

    def create(
        self,
        detection: DetectionEvent,
        enrichment: EnrichmentResult | None = None,
        triage: TriageResult | None = None,
    ) -> Incident:

        incident = Incident(
            incident_id=self._generate_incident_id(),
            detection=detection,
            enrichment=enrichment,
            triage=triage,
            risk_score=(
                triage.risk_score
                if triage is not None
                else None
            ),
        )

        with self._lock:
            self._incidents[
                incident.incident_id
            ] = incident

        return incident


    def attach_ai_assessment(
        self,
        incident_id: str,
        assessment: AIAssessment,
    ) -> Incident | None:

        with self._lock:
            incident = self._incidents.get(incident_id)

            if incident is None:
                return None

            incident.ai_assessment = assessment
            incident.updated_at = datetime.now(timezone.utc)

            return incident


    def attach_discord_message(
        self,
        incident_id: str,
        message_id: str,
    ) -> Incident | None:

        with self._lock:
            incident = self._incidents.get(
                incident_id
            )

            if incident is None:
                return None

            incident.metadata[
                "discord_message_id"
            ] = message_id

            incident.updated_at = (
                datetime.now(timezone.utc)
            )

            return incident

    def record_action(
        self,
        incident_id: str,
        action: ActionType,
        status: ActionStatus,
        analyst_id: str,
        analyst_name: str,
        result: str | None = None,
    ) -> ActionAudit | None:

        with self._lock:
            incident = self._incidents.get(incident_id)

            if incident is None:
                return None

            audit = ActionAudit(
                action_id=f"ACT-{uuid4().hex[:12].upper()}",
                incident_id=incident_id,
                action=action,
                status=status,
                analyst_id=analyst_id,
                analyst_name=analyst_name,
                target_agent=incident.detection.agent.name,
                target_pid=incident.detection.process.pid,
                result=result,
            )

            incident.action_audit.append(audit)

            incident.updated_at = datetime.now(timezone.utc)

            return audit

    def complete_action(
        self,
        incident_id: str,
        action_id: str,
        status: ActionStatus,
        result: str,
    ) -> Incident | None:

        with self._lock:
            incident = self._incidents.get(incident_id)

            if incident is None:
                return None

            audit = next(
                (
                    item
                    for item in incident.action_audit
                    if item.action_id == action_id
                ),
                None,
            )

            if audit is None:
                return None

            audit.status = status
            audit.result = result
            audit.completed_at = datetime.now(timezone.utc)

            if status == ActionStatus.SUCCESS:
                if audit.action == ActionType.ISOLATE:
                    incident.status = IncidentStatus.CONTAINED

                elif audit.action == ActionType.DISMISS:
                    incident.status = IncidentStatus.DISMISSED

            incident.updated_at = datetime.now(timezone.utc)

            return incident

    def get(
        self,
        incident_id: str,
    ) -> Incident | None:

        with self._lock:
            return self._incidents.get(
                incident_id
            )

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
    ) -> Incident | None:

        with self._lock:
            incident = self._incidents.get(
                incident_id
            )

            if incident is None:
                return None

            incident.status = status
            incident.updated_at = (
                datetime.now(timezone.utc)
            )

            return incident

    def list(self) -> list[Incident]:
        with self._lock:
            return list(
                self._incidents.values()
            )

    @staticmethod
    def _generate_incident_id() -> str:
        return (
            f"INC-{uuid4().hex[:12].upper()}"
        )


incident_store = IncidentStore()
