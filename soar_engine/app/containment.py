from __future__ import annotations

import logging

from .config import settings
from .incident import incident_store
from .schemas import (
    ActionStatus,
    ActionType,
    Incident,
)
from .services.wazuh import (
    WazuhAPIError,
    wazuh_client,
)

logger = logging.getLogger("socforge-soar")


class ContainmentExecutor:

    async def execute(
        self,
        incident: Incident,
        action: ActionType,
    ) -> tuple[ActionStatus, str]:

        if action == ActionType.DISMISS:
            return (
                ActionStatus.SUCCESS,
                "Incident dismissed by analyst.",
            )

        if not settings.socforge_containment_enabled:
            return (
                ActionStatus.BLOCKED,
                (
                    "Containment execution is disabled "
                    "by SOCFORGE_CONTAINMENT_ENABLED."
                ),
            )

        agent_id = incident.detection.agent.id

        if not agent_id:
            return (
                ActionStatus.FAILED,
                "Incident has no Wazuh agent ID.",
            )

        try:

            if action == ActionType.ISOLATE:

                result = await wazuh_client.active_response(
                    agent_id=agent_id,
                    command=settings.wazuh_isolate_command,
                )

                return (
                    ActionStatus.SUCCESS,
                    (
                        "Isolation Active Response "
                        "submitted to Wazuh: "
                        f"{result}"
                    ),
                )

            if action == ActionType.KILL:

                pid = incident.detection.process.pid

                if pid is None:
                    return (
                        ActionStatus.FAILED,
                        "Incident has no process PID.",
                    )

                result = (
                    await wazuh_client.active_response(
                        agent_id=agent_id,
                        command=(
                            settings
                            .wazuh_kill_process_command
                        ),
                        arguments=[
                            str(pid)
                        ],
                    )
                )

                return (
                    ActionStatus.SUCCESS,
                    (
                        "Process termination Active "
                        "Response submitted to Wazuh: "
                        f"{result}"
                    ),
                )

            if action == ActionType.DISMISS:

                return (
                    ActionStatus.SUCCESS,
                    "Incident dismissed by analyst.",
                )

            return (
                ActionStatus.FAILED,
                f"Unsupported action: {action}",
            )

        except WazuhAPIError as exc:

            logger.error(
                "Wazuh containment failed: %s",
                exc,
            )

            return (
                ActionStatus.FAILED,
                str(exc),
            )


containment_executor = ContainmentExecutor()
