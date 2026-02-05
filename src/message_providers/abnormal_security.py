import logging
import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from common import Message, MessageFetcher

logger = logging.getLogger(__name__)

ABNORMAL_API_KEY_ENV_VAR = "ABNORMAL_API_KEY"
LOOKBACK_MINUTES_ENV_VAR = "MESSAGE_LOOKBACK_MINUTES"

API_BASE_URL = "https://api.abnormalplatform.com/v1"
HTTP_TIMEOUT_SECONDS = 60
DEFAULT_LOOKBACK_MINUTES = 5
DEFAULT_PAGE_SIZE = 100

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0
MAX_RETRY_DELAY = 60.0
BACKOFF_MULTIPLIER = 2.0


class AbnormalSecurityFetcher(MessageFetcher):
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = API_BASE_URL,
        lookback_minutes: Optional[int] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ):
        self.api_key = api_key or os.getenv(ABNORMAL_API_KEY_ENV_VAR)

        if not self.api_key:
            raise ValueError(
                "Abnormal Security API key is required. "
                f"Set {ABNORMAL_API_KEY_ENV_VAR} environment variable "
                "or pass it as a constructor argument."
            )

        self.base_url = base_url
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
        self.page_size = page_size

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        )

    def _make_request_with_retry(
        self, method: str, url: str, **kwargs
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with exponential backoff retry logic.

        Retries on 429, 5xx, timeouts, and connection errors. Returns None if all retries exhausted.
        """
        delay = INITIAL_RETRY_DELAY

        for attempt in range(MAX_RETRIES):
            if attempt == MAX_RETRIES:
                logger.error(f"Exhausted {MAX_RETRIES} retry attempts: {url}")
                return None
            elif attempt > 0:
                time.sleep(delay)
                delay = min(delay * BACKOFF_MULTIPLIER, MAX_RETRY_DELAY)

            try:
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 429:
                    logger.warning(
                        f"Rate limited (429) on {method} {url}, "
                        f"retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    continue
                elif response.status_code >= 500:
                    logger.warning(
                        f"Server error ({response.status_code}) on {method} {url}, "
                        f"retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    continue

                response.raise_for_status()
                return response

            except requests.Timeout:
                logger.warning(
                    f"Timeout on {method} {url}, "
                    f"retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                )
                continue

            except requests.ConnectionError as e:
                logger.warning(
                    f"Connection error on {method} {url}: {e}, "
                    f"retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                )
                continue

            except requests.RequestException as e:
                logger.error(f"Request failed for {method} {url}: {e}")
                return None

        return None

    def _fetch_remediated_threats(self) -> list[str]:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=self.lookback_minutes)

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_str = f"latestTimeRemediated gte {start_str} lte {end_str}"

        all_threat_ids = []
        page_number = 1

        while True:
            response = self._make_request_with_retry(
                "GET",
                f"{self.base_url}/threats",
                params={
                    "filter": filter_str,
                    "pageSize": str(self.page_size),
                    "pageNumber": str(page_number),
                },
                timeout=HTTP_TIMEOUT_SECONDS,
            )

            if not response:
                logger.error(f"Failed to fetch threats page {page_number}")
                break

            data = response.json()
            threats = data.get("threats", [])

            if not threats:
                break

            threat_ids = [t["threatId"] for t in threats]
            all_threat_ids.extend(threat_ids)

            next_page = data.get("nextPageNumber")
            if not next_page:
                break

            logger.info(f"Fetched page {page_number}, now fetching page {next_page}")
            page_number = next_page

        return all_threat_ids

    def _get_threat_messages(self, threat_id: str) -> list[tuple[str, str]]:
        """Return list of (message_id_str, recipient) tuples."""
        response = self._make_request_with_retry(
            "GET",
            f"{self.base_url}/threats/{threat_id}",
            timeout=HTTP_TIMEOUT_SECONDS,
        )

        if not response:
            logger.error(f"Failed to get threat details for {threat_id}")
            return []

        data = response.json()
        messages = data.get("messages", [])

        result = []
        for msg in messages:
            message_id_str = msg.get("abxMessageIdStr")
            recipient = msg.get("recipientAddress")
            if message_id_str and recipient:
                result.append((message_id_str, recipient))

        return result

    def _download_message(self, message_id_str: str) -> Optional[str]:
        """Download full message in EML format."""
        response = self._make_request_with_retry(
            "GET",
            f"{self.base_url}/messages/{message_id_str}/download",
            timeout=HTTP_TIMEOUT_SECONDS,
        )

        if not response:
            logger.error(f"Failed to download message {message_id_str}")
            return None

        return response.text

    def yield_remediated_emails(self) -> Iterator[Message]:
        """Yield remediated emails, skipping any that cannot be retrieved."""
        threats = self._fetch_remediated_threats()
        logger.info(f"Found {len(threats)} remediated threats to process")

        for threat_id in threats:
            try:
                messages = self._get_threat_messages(threat_id)

                if not messages:
                    continue

                for message_id_str, recipient in messages:
                    raw_message = self._download_message(message_id_str)
                    if not raw_message:
                        continue

                    yield Message(user_id=recipient, raw=raw_message)

            except Exception as e:
                logger.error(f"Error processing threat {threat_id}: {e}")
                continue
