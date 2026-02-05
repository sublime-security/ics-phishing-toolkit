import logging
import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from common import Message, MessageFetcher

logger = logging.getLogger(__name__)

PROOFPOINT_CLIENT_ID_ENV_VAR = "PROOFPOINT_CLIENT_ID"
PROOFPOINT_CLIENT_SECRET_ENV_VAR = "PROOFPOINT_CLIENT_SECRET"
LOOKBACK_MINUTES_ENV_VAR = "MESSAGE_LOOKBACK_MINUTES"

TOKEN_BASE_URL = "https://auth.proofpoint.com/v1/token"
API_BASE_URL = "https://threatprotection-api.proofpoint.com"

HTTP_TIMEOUT_SECONDS = 60
DEFAULT_LOOKBACK_MINUTES = 5
TOKEN_EXPIRY_BUFFER_SECONDS = 300
FETCH_IN_PROGRESS_SLEEP_SECONDS = 5
THROTTLED_SLEEP_SECONDS = 30
POLLING_TIMEOUT_SECONDS = 180


class ProofpointCloudFetcher(MessageFetcher):
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        lookback_minutes: Optional[int] = None,
        batch_size: int = 200,
    ):
        self.client_id = client_id or os.getenv(PROOFPOINT_CLIENT_ID_ENV_VAR)
        self.client_secret = client_secret or os.getenv(PROOFPOINT_CLIENT_SECRET_ENV_VAR)

        if not self.client_id or not self.client_secret:
            raise ValueError(
                f"Proofpoint credentials are required. "
                f"Set {PROOFPOINT_CLIENT_ID_ENV_VAR} and "
                f"{PROOFPOINT_CLIENT_SECRET_ENV_VAR} environment variables "
                "or pass them as constructor arguments."
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
        self.batch_size = batch_size

        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._refresh_access_token()

    def _refresh_access_token(self) -> None:
        response = requests.post(
            TOKEN_BASE_URL,
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
        expires_in = token_data.get("expires_in", 3600)
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        self.session.headers.update({"Authorization": f"Bearer {self._access_token}"})
        logger.info(f"Access token refreshed, expires in {expires_in} seconds")

    def _ensure_valid_token(self) -> None:
        if not self._token_expires_at:
            self._refresh_access_token()
        else:
            expiry_with_buffer = self._token_expires_at - timedelta(
                seconds=TOKEN_EXPIRY_BUFFER_SECONDS
            )
            if datetime.now(timezone.utc) >= expiry_with_buffer:
                self._refresh_access_token()

    def yield_remediated_emails(self) -> Iterator[Message]:
        self._ensure_valid_token()
        messages = self._fetch_quarantined_messages()
        logger.info(f"Found {len(messages)} quarantined messages to process")

        for msg_info in messages:
            message_id = msg_info.get("id")
            recipient = msg_info.get("recipient_address")

            if not recipient:
                logger.warning(f"Skipping message {message_id}: no recipient address")
                continue

            raw_message = self._download_raw_message(message_id)
            if raw_message:
                yield Message(user_id=recipient, raw=raw_message)
            else:
                logger.warning(f"Failed to download message {message_id} for {recipient}")

    def _fetch_quarantined_messages(self) -> list:
        self._ensure_valid_token()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=self.lookback_minutes)

        logger.info(f"Fetching quarantined messages from {start_time} to {end_time}")

        all_messages = []
        start_row = 0

        while True:
            end_row = start_row + self.batch_size

            response = self.session.post(
                f"{API_BASE_URL}/api/v1/tric/messages",
                json={
                    "startRow": start_row,
                    "endRow": end_row,
                    "sortParams": [{"sort": "desc", "colId": "received_time"}],
                    "filters": {
                        "source_filters": ["tap", "smart_search"],
                        "quarantine_filters": ["quarantine_success"],
                        "time_range_filter": {
                            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                        },
                    },
                },
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            messages = response.json().get("messages", [])

            if not messages:
                break

            all_messages.extend(messages)

            if len(messages) < self.batch_size:
                break

            start_row = end_row

        logger.info(f"Retrieved {len(all_messages)} total messages from Proofpoint API")
        return all_messages

    def _download_raw_message(self, message_id: str) -> Optional[str]:
        self._ensure_valid_token()

        # message must be fetched before it can be downloaded
        fetch_url = f"{API_BASE_URL}/api/v1/tric/messages/{message_id}/fetch"
        status_url = f"{API_BASE_URL}/api/v1/tric/messages/{message_id}/fetchStatus"

        logger.debug(f"Initiating fetch for message {message_id}")

        try:
            fetch_response = self.session.get(fetch_url, timeout=HTTP_TIMEOUT_SECONDS)
            fetch_response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to initiate fetch for message {message_id}: {e}")
            return None

        start_time = time.time()

        while True:
            if time.time() - start_time > POLLING_TIMEOUT_SECONDS:
                logger.error(
                    f"Timeout exceeded ({POLLING_TIMEOUT_SECONDS}s)"
                    f" while waiting for message {message_id}"
                )
                return None

            try:
                status_response = self.session.get(status_url, timeout=HTTP_TIMEOUT_SECONDS)
                status_response.raise_for_status()
                status_data = status_response.json()
                status = status_data.get("messageStatus")
            except requests.RequestException as e:
                logger.error(f"Failed to check status for message {message_id}: {e}")
                return None

            if status == "fetched":
                logger.debug(f"Message {message_id} is ready for download")
                break
            elif status == "fetch_in_progress":
                logger.debug(
                    f"Message {message_id} fetch in progress,"
                    f" waiting {FETCH_IN_PROGRESS_SLEEP_SECONDS}s"
                )
                time.sleep(FETCH_IN_PROGRESS_SLEEP_SECONDS)
            elif status == "throttled":
                logger.warning(
                    f"Message {message_id} fetch throttled, waiting {THROTTLED_SLEEP_SECONDS}s"
                )
                time.sleep(THROTTLED_SLEEP_SECONDS)
            else:
                logger.error(f"Unexpected status '{status}' for message {message_id}")
                return None

        try:
            response = self.session.get(
                f"{API_BASE_URL}/api/v1/tric/messages/{message_id}/download",
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            logger.debug(f"Successfully downloaded raw message {message_id}")
            return response.text
        except requests.RequestException as e:
            logger.error(f"Failed to download message {message_id}: {e}")
            return None
