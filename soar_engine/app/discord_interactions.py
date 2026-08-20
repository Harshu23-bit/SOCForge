from __future__ import annotations

import logging
import asyncio

from fastapi import APIRouter, Header, HTTPException, Request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from datetime import datetime, timezone

from .config import settings
from .incident import incident_store
from .containment import containment_executor
from .notifier import update_incident_message
from .schemas import (
    ActionStatus,
    ActionType,
)

logger = logging.getLogger("socforge-soar")

router = APIRouter(
    prefix="/api/v1",
    tags=["Discord"],
)


def verify_discord_signature(
    body: bytes,
    signature: str | None,
    timestamp: str | None,
) -> None:
    """
    Verify that the interaction was signed by Discord.
    """

    if not signature or not timestamp:
        raise HTTPException(
            status_code=401,
            detail="Missing Discord signature headers.",
        )

    if not settings.discord_public_key:
        logger.error(
            "Discord public key is not configured."
        )
        raise HTTPException(
            status_code=500,
            detail=(
                "DISCORD_PUBLIC_KEY is not configured."
            ),
        )

    try:
        verify_key = VerifyKey(
            bytes.fromhex(
                settings.discord_public_key
            )
        )

        verify_key.verify(
            timestamp.encode("utf-8") + body,
            bytes.fromhex(signature),
        )

    except (
        BadSignatureError,
        ValueError,
    ):
        logger.warning(
            "Rejected Discord interaction with "
            "invalid signature."
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid Discord request signature.",
        )


def extract_discord_user(
    payload: dict,
) -> tuple[str, str]:
    """
    Return Discord user ID and display/username.

    Guild interactions provide member.user.
    DM interactions can provide user directly.
    """

    member_user = (
        payload
        .get("member", {})
        .get("user", {})
    )

    user = payload.get("user", {})

    source = (
        member_user
        if member_user
        else user
    )

    user_id = str(
        source.get("id", "unknown")
    )

    username = (
        source.get("global_name")
        or source.get("username")
        or "unknown"
    )

    return user_id, username


def parse_action_custom_id(
    custom_id: str,
) -> tuple[str, str] | None:
    """
    Expected format:

        incident:<incident_id>:<action>
    """

    parts = custom_id.split(":")

    if len(parts) != 3:
        return None

    prefix, incident_id, action = parts

    if prefix != "incident":
        return None

    if not incident_id or not action:
        return None

    if action not in {
        "isolate",
        "kill",
        "dismiss",
    }:
        return None

    return incident_id, action


def _action_type(
    action: str,
) -> ActionType:

    mapping = {
        "isolate": ActionType.ISOLATE,
        "kill": ActionType.KILL,
        "dismiss": ActionType.DISMISS,
    }

    try:
        return mapping[action]
    except KeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="Unsupported action.",
        ) from exc


async def _execute_discord_action(
    incident_id: str,
    action: ActionType,
    action_id: str,
    analyst_name: str,
) -> None:

    try:
        incident = incident_store.get(
            incident_id
        )

        if incident is None:
            return

        incident_store.complete_action(
            incident_id=incident_id,
            action_id=action_id,
            status=ActionStatus.EXECUTING,
            result="Action execution started.",
        )

        if action == ActionType.DISMISS:

            updated = incident_store.complete_action(
                incident_id=incident_id,
                action_id=action_id,
                status=ActionStatus.SUCCESS,
                result="Incident dismissed by analyst.",
            )

            if updated is None:
                return

            await update_incident_message(
                incident=updated,
                action_status=ActionStatus.SUCCESS,
                analyst_name=analyst_name,
                result="Incident dismissed by analyst.",
            )

            return

        # Isolate / Kill go through the containment layer.
        status, result = (
            await containment_executor.execute(
                incident,
                action,
            )
        )

        updated = incident_store.complete_action(
            incident_id=incident_id,
            action_id=action_id,
            status=status,
            result=result,
        )

        logger.info(
            "ACTION AUDIT COMPLETED: incident=%s action=%s status=%s",
            incident_id,
            action_id,
            status,
        )

        if updated is None:
            return

        await update_incident_message(
            incident=updated,
            action_status=status,
            analyst_name=analyst_name,
            result=result,
        )

    except Exception:
        logger.exception(
            "Unhandled Discord action failure: "
            "incident=%s action=%s audit=%s",
            incident_id,
            action,
            action_id,
        )

    incident_store.complete_action(
            incident_id=incident_id,
            action_id=action_id,
            status=ActionStatus.FAILED,
            result=(
                "Unhandled exception during action execution."
            ),
        )

@router.post("/interactions")
async def discord_interaction(
    request: Request,
    x_signature_ed25519: str | None = Header(
        default=None,
        alias="X-Signature-Ed25519",
    ),
    x_signature_timestamp: str | None = Header(
        default=None,
        alias="X-Signature-Timestamp",
    ),
):
    body = await request.body()

    # Signature verification must happen before trusting payload.
    verify_discord_signature(
        body,
        x_signature_ed25519,
        x_signature_timestamp,
    )

    try:
        payload = await request.json()
    except Exception as exc:
        logger.exception(
            "Failed to decode Discord interaction JSON."
        )
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON payload.",
        ) from exc

    interaction_type = payload.get("type")

    # Discord PING validation.
    if interaction_type == 1:
        return {
            "type": 1
        }

    # Message component / button interaction.
    if interaction_type != 3:
        return {
            "type": 4,
            "data": {
                "content": (
                    "⚠️ Unsupported Discord interaction."
                ),
                "flags": 64,
            },
        }

    data = payload.get("data", {})

    custom_id = data.get(
        "custom_id",
        "",
    )

    parsed = parse_action_custom_id(
        custom_id
    )

    if parsed is None:
        return {
            "type": 4,
            "data": {
                "content": (
                    "⚠️ Invalid SOCForge action."
                ),
                "flags": 64,
            },
        }

    incident_id, action = parsed

    incident = incident_store.get(
        incident_id
    )

    if incident is None:
        return {
            "type": 4,
            "data": {
                "content": (
                    f"⚠️ Incident `{incident_id}` "
                    "is no longer available."
                ),
                "flags": 64,
            },
        }

    user_id, username = extract_discord_user(
        payload
    )

    try:
        action_type = _action_type(action)

        audit = incident_store.record_action(
            incident_id=incident_id,
            action=action_type,
            status=ActionStatus.REQUESTED,
            analyst_id=user_id,
            analyst_name=username,
            result="Action received from Discord.",
        )

        if audit is None:
            raise HTTPException(
                status_code=500,
                detail="Unable to create action audit.",
            )

        logger.info(
            "ACTION AUDIT CREATED: %s",
            audit.model_dump(),
        )

        logger.info(
           "Discord action received: "
           "incident=%s action=%s analyst=%s (%s)",
           incident_id,
           action,
           username,
           user_id,
        )

        # Immediate Discord acknowledgement.
        # Actual execution happens after acknowledgement.
        asyncio.create_task(
            _execute_discord_action(
                incident_id=incident_id,
                action=action_type,
                action_id=audit.action_id,
                analyst_name=username,
            )
        )

        return {
            "type": 4,
            "data": {
                "content": (
                    f"🛡️ **SOCForge action received**\n"
                    f"Incident: `{incident_id}`\n"
                    f"Action: `{action_type.value}`\n"
                    f"Analyst: **{username}**\n\n"
                    "Execution started."
                ),
                "flags": 64,
            },
        }

    except Exception as exc:
        logger.exception(
            "Discord interaction processing failed."
        )

        return {
            "type": 4,
            "data": {
                "content": (
                    "❌ SOCForge could not process "
                    "this action."
                ),
                "flags": 64,
            },
        }
