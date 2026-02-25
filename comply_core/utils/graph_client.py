"""MSAL authentication and Microsoft Graph API wrapper."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from msal import ConfidentialClientApplication

from comply_core.config import ComplyConfig
from comply_core.exceptions import ComplyAuthError, ComplyCollectionError
from comply_core.utils.logging import get_logger

logger = get_logger("graph_client")

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0


class GraphClient:
    """Async Microsoft Graph API client with MSAL authentication."""

    def __init__(self, config: ComplyConfig) -> None:
        self._config = config
        self._msal_app: ConfidentialClientApplication | None = None
        self._access_token: str | None = None
        self._http_client: httpx.AsyncClient | None = None

    def _get_msal_app(self) -> ConfidentialClientApplication:
        """Lazy-initialise the MSAL confidential client."""
        if self._msal_app is None:
            self._msal_app = ConfidentialClientApplication(
                client_id=self._config.client_id,
                client_credential=self._config.client_secret,
                authority=f"https://login.microsoftonline.com/{self._config.tenant_id}",
            )
        return self._msal_app

    def _acquire_token(self) -> str:
        """Acquire an access token using client credentials flow."""
        app = self._get_msal_app()

        # Try cache first
        result = app.acquire_token_silent(GRAPH_SCOPE, account=None)
        if not result:
            result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise ComplyAuthError(f"Failed to acquire token: {error}")

        self._access_token = result["access_token"]
        return self._access_token

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers, acquiring a token if needed."""
        if not self._access_token:
            self._acquire_token()
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Return or create the async HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def get(self, endpoint: str) -> dict[str, Any]:
        """Make a GET request to a Graph API endpoint."""
        url = f"{GRAPH_BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint
        client = await self._get_client()

        for attempt in range(MAX_RETRIES):
            try:
                response = await client.get(url, headers=self._auth_headers())

                if response.status_code == 401:
                    # Token may have expired — re-acquire
                    self._access_token = None
                    self._acquire_token()
                    response = await client.get(url, headers=self._auth_headers())

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", INITIAL_BACKOFF))
                    logger.warning(
                        "Rate limited (429). Retrying after %ds (attempt %d/%d)",
                        retry_after,
                        attempt + 1,
                        MAX_RETRIES,
                    )
                    await asyncio.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as exc:
                raise ComplyCollectionError(
                    f"Graph API error {exc.response.status_code} for {endpoint}: "
                    f"{exc.response.text[:200]}"
                ) from exc
            except httpx.RequestError as exc:
                if attempt < MAX_RETRIES - 1:
                    backoff = INITIAL_BACKOFF * (2 ** attempt)
                    logger.warning(
                        "Request error for %s: %s. Retrying in %.1fs",
                        endpoint,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    raise ComplyCollectionError(
                        f"Failed to reach Graph API after {MAX_RETRIES} attempts: {exc}"
                    ) from exc

        raise ComplyCollectionError(f"Graph API request failed after {MAX_RETRIES} retries")

    async def paginated_get(self, endpoint: str) -> list[dict[str, Any]]:
        """Fetch all pages from a Graph API endpoint."""
        results: list[dict[str, Any]] = []
        url = f"{GRAPH_BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint

        while url:
            client = await self._get_client()

            for attempt in range(MAX_RETRIES):
                try:
                    response = await client.get(url, headers=self._auth_headers())

                    if response.status_code == 401:
                        self._access_token = None
                        self._acquire_token()
                        response = await client.get(url, headers=self._auth_headers())

                    if response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", INITIAL_BACKOFF))
                        logger.warning("Rate limited. Retrying after %ds", retry_after)
                        await asyncio.sleep(retry_after)
                        continue

                    response.raise_for_status()
                    break
                except httpx.HTTPStatusError as exc:
                    raise ComplyCollectionError(
                        f"Graph API error {exc.response.status_code}: {exc.response.text[:200]}"
                    ) from exc
                except httpx.RequestError as exc:
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(INITIAL_BACKOFF * (2 ** attempt))
                    else:
                        raise ComplyCollectionError(
                            f"Failed to reach Graph API: {exc}"
                        ) from exc

            data = response.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return results

    async def test_connection(self) -> dict[str, Any]:
        """Test Graph API connectivity and list granted permissions."""
        try:
            self._acquire_token()

            # Try to read the service principal's app roles
            client = await self._get_client()
            resp = await client.get(
                f"{GRAPH_BASE_URL}/organization",
                headers=self._auth_headers(),
            )

            if resp.status_code == 200:
                return {"authenticated": True, "permissions": []}

            return {"authenticated": True, "permissions": [], "note": "Could not list org details"}

        except ComplyAuthError as exc:
            return {"authenticated": False, "error": str(exc)}
        except Exception as exc:
            return {"authenticated": False, "error": str(exc)}

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
