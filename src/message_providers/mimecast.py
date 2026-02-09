import logging
import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, cast

import requests

from common import Message, MessageFetcher

logger = logging.getLogger(__name__)

MIMECAST_CLIENT_ID_ENV_VAR = "MIMECAST_CLIENT_ID"
MIMECAST_CLIENT_SECRET_ENV_VAR = "MIMECAST_CLIENT_SECRET"
MIMECAST_REGION_ENV_VAR = "MIMECAST_REGION"
LOOKBACK_MINUTES_ENV_VAR = "MESSAGE_LOOKBACK_MINUTES"

# https://developer.services.mimecast.com/api-overview
OAUTH_TOKEN_URLS = {
    "global": "https://api.services.mimecast.com/oauth/token",
    "us": "https://us-api.services.mimecast.com/oauth/token",
    "uk": "https://uk-api.services.mimecast.com/oauth/token",
}

API_BASE_URLS = {
    "global": "https://api.services.mimecast.com",
    "us": "https://us-api.services.mimecast.com",
    "uk": "https://uk-api.services.mimecast.com",
}

HTTP_TIMEOUT_SECONDS = 60
DEFAULT_LOOKBACK_MINUTES = 5
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # Refresh token 5 minutes before expiry
ARCHIVE_SEARCH_REASON = "Searching for malicious calendar events"


class MimecastFetcher(MessageFetcher):
    """Fetches remediated messages from Mimecast Threat Remediation API 2.0.

    Implements a 3-step workflow:
    1. Find remediation incidents within lookback window
    2. Search archive for each incident's message
    3. Download raw RFC822 message content

    Uses OAuth 2.0 authentication with Client Credentials grant.

    See for reference:
    - https://developer.services.mimecast.com/api-overview
    - https://developer.services.mimecast.com/docs/threatmanagement/1/routes/api/ttp/remediation/find-incidents/post
    - https://developer.services.mimecast.com/docs/cloudgateway/1/routes/api/message-finder/search/post
    - https://developer.services.mimecast.com/docs/archivedataaccess/1/routes/api/archive/get-message-part/post

    Required Permissions:
    - Gateway | Tracking | Read: Required for message-finder/search API
    - Archive | Search Content View: Required for archive/get-message-part API
      (or the authenticated user must be the mailbox owner)
    - Threat Intelligence | Remediation | Read: Required for find-incidents API
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        region: Optional[str] = None,
        lookback_minutes: Optional[int] = None,
        max_retries: int = 3,
    ):
        """Initialize Mimecast API 2.0 client with OAuth 2.0 credentials.

        Args:
            client_id: OAuth 2.0 client ID
            client_secret: OAuth 2.0 client secret
            region: API region (global, us, or uk). Defaults to global for best performance.
            lookback_minutes: Minutes to look back for remediation incidents.
                Defaults to 5 minutes
            max_retries: Maximum number of retry attempts for rate-limited or server error
                responses
        """
        self.client_id = client_id or os.getenv(MIMECAST_CLIENT_ID_ENV_VAR)
        self.client_secret = client_secret or os.getenv(MIMECAST_CLIENT_SECRET_ENV_VAR)
        region = region or os.getenv(MIMECAST_REGION_ENV_VAR, "global")

        if not self.client_id or not self.client_secret:
            raise ValueError(
                f"Mimecast credentials are required. Set {MIMECAST_CLIENT_ID_ENV_VAR}"
                f" and {MIMECAST_CLIENT_SECRET_ENV_VAR} environment variables"
                " or pass them as constructor arguments."
            )

        if lookback_minutes is None:
            lookback_minutes_str = os.getenv(LOOKBACK_MINUTES_ENV_VAR)
            try:
                lookback_minutes = int(lookback_minutes_str or DEFAULT_LOOKBACK_MINUTES)
            except ValueError as e:
                raise ValueError(
                    f"{LOOKBACK_MINUTES_ENV_VAR} must be a valid integer,"
                    f" got '{lookback_minutes_str}'"
                ) from e

        self.lookback_minutes = lookback_minutes

        if self.lookback_minutes <= 0:
            raise ValueError(
                f"lookback_minutes must be a positive integer, got {self.lookback_minutes}"
            )
        self.max_retries = max_retries

        if region in API_BASE_URLS:
            self.base_url = API_BASE_URLS[region]
            self.token_url = OAUTH_TOKEN_URLS[region]
        else:
            raise ValueError(
                f"Invalid region '{region}'. Must be one of: {', '.join(API_BASE_URLS.keys())}"
            )

        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._refresh_access_token()

    def _refresh_access_token(self) -> None:
        """Obtain a new OAuth 2.0 access token using Client Credentials grant."""
        response = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        token_data = response.json()

        self._access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 1800)
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        self.session.headers.update({"Authorization": f"Bearer {self._access_token}"})

    def _ensure_valid_token(self) -> None:
        """Ensure the OAuth token is valid, refreshing if necessary."""
        if not self._token_expires_at:
            self._refresh_access_token()
        else:
            expiry_with_buffer = self._token_expires_at - timedelta(
                seconds=TOKEN_EXPIRY_BUFFER_SECONDS
            )
            if datetime.now(timezone.utc) >= expiry_with_buffer:
                self._refresh_access_token()

    def _should_retry_request(self, exception: requests.RequestException) -> bool:
        """Determine if a request should be retried (429 or 5xx errors)."""
        if hasattr(exception, "response") and exception.response is not None:
            status_code = exception.response.status_code
            return status_code == 429 or status_code >= 500
        return False

    def _make_request(self, endpoint: str, payload: dict) -> Any:
        """Make authenticated POST request with retry logic and exponential backoff."""
        url = f"{self.base_url}{endpoint}"

        for attempt in range(self.max_retries + 1):
            self._ensure_valid_token()

            try:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                return response.json()

            except requests.RequestException as e:
                is_last_attempt = attempt == self.max_retries

                if self._should_retry_request(e) and not is_last_attempt:
                    wait_time = 2**attempt
                    logger.warning(
                        f"Request to {endpoint} failed "
                        f"(attempt {attempt + 1}/{self.max_retries + 1}). "
                        f"Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue

                raise

    def _find_remediation_incidents(self, start_time: datetime, end_time: datetime) -> list:
        """Find remediation incidents within window."""
        logger.info(f"Fetching remediation incidents from {start_time} to {end_time}")

        all_incidents: list[Any] = []
        page_token = None
        page_count = 0

        while True:
            page_count += 1
            payload: dict[str, Any] = {
                "meta": {"pagination": {"pageSize": 100}},
                "data": [
                    {
                        "start": start_time.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                        "end": end_time.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                        "filterBy": {
                            "fieldName": "type",
                            "value": "automatic,manual",
                        },
                    }
                ],
            }

            if page_token:
                payload["meta"]["pagination"]["pageToken"] = page_token

            response = self._make_request("/api/ttp/remediation/find-incidents", payload)
            data = response.get("data", [])
            incidents = data[0].get("incidents", []) if data else []
            all_incidents.extend(incidents)

            pagination = response.get("meta", {}).get("pagination", {})
            page_token = pagination.get("next")

            if not page_token:
                break

        logger.info(
            f"Found {len(all_incidents)} total remediation incidents across {page_count} page(s)"
        )
        return all_incidents

    def _search_archive_for_message(
        self, message_id: str, start: datetime, end: datetime
    ) -> Optional[str]:
        """Search archive for a message, returning its archive ID or None if not found."""
        payload = {
            "data": [
                {
                    "searchReason": ARCHIVE_SEARCH_REASON,
                    "messageId": message_id,
                    "start": start.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                    "end": end.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                }
            ]
        }

        try:
            response = self._make_request("/api/message-finder/search", payload)
            data = response.get("data", [])
            messages = data[0].get("trackedEmails", []) if data else []

            if not messages:
                logger.warning(f"Message {message_id} not found in archive")
                return None

            archive_id = messages[0].get("id")
            return cast("Optional[str]", archive_id)

        except requests.RequestException as e:
            logger.error(f"Failed to search archive for message {message_id}: {e}")
            return None

    def _get_raw_message(self, archive_id: str, recipient: str) -> Optional[str]:
        """Download raw RFC822 message content from archive.

        Note: API returns a pre-signed URL in the response that must be fetched
        to retrieve the actual RFC822 content.
        """
        endpoint = "/api/archive/get-message-part"
        payload = {
            "data": [
                {
                    "mailbox": recipient,
                    "id": archive_id,
                    "context": "RECEIVED",
                    "type": "RFC822",
                }
            ]
        }

        url = f"{self.base_url}{endpoint}"

        for attempt in range(self.max_retries + 1):
            self._ensure_valid_token()

            try:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                response.raise_for_status()

                response_data = response.json()

                if "fail" in response_data and response_data["fail"]:
                    logger.error(f"API error for archive ID {archive_id}: {response_data}")
                    return None

                data = response_data.get("data", [])
                if not data or not data[0].get("url"):
                    logger.error(f"No URL in response for archive ID {archive_id}: {response_data}")
                    return None

                presigned_url = data[0]["url"]

                download_response = requests.get(presigned_url, timeout=HTTP_TIMEOUT_SECONDS)
                download_response.raise_for_status()

                return download_response.text

            except requests.RequestException as e:
                is_last_attempt = attempt == self.max_retries

                if self._should_retry_request(e) and not is_last_attempt:
                    wait_time = 2**attempt
                    logger.warning(
                        f"Failed to download message {archive_id} "
                        f"(attempt {attempt + 1}/{self.max_retries + 1}). "
                        f"Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue

                logger.error(f"Failed to download message {archive_id}: {e}")
                return None

        return None

    def yield_remediated_emails(self) -> Iterator[Message]:
        """Yield remediated emails, skipping any that cannot be retrieved."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=self.lookback_minutes)

        incidents = self._find_remediation_incidents(start_time, end_time)

        for incident in incidents:
            incident_code = incident.get("code", "unknown")
            search_criteria = incident.get("searchCriteria", {})

            message_ids = []
            if "messageId" in search_criteria and search_criteria["messageId"]:
                message_ids.append(search_criteria["messageId"])
            if "messageIds" in search_criteria:
                ids_list = search_criteria["messageIds"]
                if isinstance(ids_list, list):
                    message_ids.extend(ids_list)

            unique_message_ids = set(message_ids)

            if not unique_message_ids:
                logger.warning(
                    f"Skipping incident {incident_code}: no messageId or messageIds in searchCriteria"
                )
                continue

            recipient = search_criteria.get("to")
            if not recipient:
                logger.warning(f"Skipping incident {incident_code}: no recipient in searchCriteria")
                continue

            for message_id in unique_message_ids:
                archive_id = self._search_archive_for_message(message_id, start_time, end_time)
                if not archive_id:
                    logger.warning(
                        f"Failed to find message {message_id} in archive for incident {incident_code}"
                    )
                    continue

                raw_message = self._get_raw_message(archive_id, recipient)
                if raw_message:
                    yield Message(user_id=recipient, raw=raw_message)
                else:
                    logger.warning(
                        f"Failed to download message {archive_id} for incident {incident_code}"
                    )
