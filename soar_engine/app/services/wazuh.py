from __future__ import annotations

import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger("socforge-soar")


class WazuhAPIError(RuntimeError):
    pass


class WazuhClient:
    """
    Minimal async Wazuh Server API client.

    Authentication uses the Wazuh API JWT flow.
    """

    def __init__(self) -> None:
        self.base_url = (
            settings.wazuh_api_url.rstrip("/")
        )

        self.username = (
            settings.wazuh_api_username
        )

        self.password = (
            settings.wazuh_api_password
        )

        self.verify_ssl = settings.wazuh_verify_ssl

        self._token: str | None = None

    async def authenticate(self) -> str:
        if (
            not self.base_url
            or not self.username
            or not self.password
        ):
            raise WazuhAPIError(
                "Wazuh API configuration is incomplete."
            )

        url = (
            f"{self.base_url}"
            "/security/user/authenticate"
        )

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(10.0),
            ) as client:

                response = await client.post(
                    url,
                    auth=(
                        self.username,
                        self.password,
                    ),
                )

        except httpx.HTTPError as exc:
            raise WazuhAPIError(
                "Wazuh authentication request failed."
            ) from exc

        if response.status_code != 200:
            raise WazuhAPIError(
                "Wazuh authentication failed: "
                f"HTTP {response.status_code}"
            )

        data = response.json()

        token = (
            data
            .get("data", {})
            .get("data")
        )

        if not token:
            raise WazuhAPIError(
                "Wazuh authentication returned no JWT."
            )

        self._token = token

        return token

    async def _get_token(self) -> str:
        if self._token:
            return self._token

        return await self.authenticate()

    async def active_response(
        self,
        agent_id: str,
        command: str,
        arguments: list[str] | None = None,
    ) -> dict[str, Any]:

        token = await self._get_token()

        url = (
            f"{self.base_url}"
            "/active-response"
        )

        payload: dict[str, Any] = {
            "command": command,
            "arguments": arguments or [],
        }

        params = {
            "agents_list": agent_id,
            "wait_for_complete": "true",
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(15.0),
            ) as client:

                response = await client.put(
                    url,
                    params=params,
                    headers=headers,
                    json=payload,
                )

        except httpx.HTTPError as exc:
            raise WazuhAPIError(
                "Wazuh Active Response request failed."
            ) from exc

        if response.status_code == 401:
            self._token = None

            token = await self.authenticate()

            headers["Authorization"] = (
                f"Bearer {token}"
            )

            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(15.0),
            ) as client:

                response = await client.put(
                    url,
                    params=params,
                    headers=headers,
                    json=payload,
                )

        if response.status_code != 200:
            raise WazuhAPIError(
                "Wazuh Active Response failed: "
                f"HTTP {response.status_code}"
            )

        return response.json()


wazuh_client = WazuhClient()
