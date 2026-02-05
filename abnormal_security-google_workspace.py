import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import message_from_string
from typing import Any, Callable, Literal, Optional, cast

import jwt
import requests

ABNORMAL_API_KEY_ENV_VAR = "ABNORMAL_API_KEY"
LOOKBACK_MINUTES_ENV_VAR = "MESSAGE_LOOKBACK_MINUTES"
GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_FILE"
GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_JSON"
GOOGLE_ACCESS_TOKEN_ENV_VAR = "GOOGLE_ACCESS_TOKEN"
MODE_ENV_VAR = "ICS_PHISHING_REMEDIATION_MODE"

API_BASE_URL = "https://api.abnormalplatform.com/v1"
HTTP_TIMEOUT_SECONDS = 60
DEFAULT_LOOKBACK_MINUTES = 5
DEFAULT_PAGE_SIZE = 100
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0
MAX_RETRY_DELAY = 60.0
BACKOFF_MULTIPLIER = 2.0
TOKEN_EXPIRY_BUFFER_SECONDS = 300
CALENDAR_API_BASE_URL = "https://www.googleapis.com/calendar/v3"
CURRENT_USER_CALENDAR_KEYWORD = "primary"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/calendar.events"
MODE_DRY_RUN = "dry_run"
MODE_DELETE_EVENTS = "delete_events"
VALID_MODES = (MODE_DRY_RUN, MODE_DELETE_EVENTS)
DEFAULT_MODE = MODE_DRY_RUN
logger = logging.getLogger(__name__)
Mode = Literal["dry_run", "delete_events"]


@dataclass
class Message:
    user_id: str
    raw: str


@dataclass
class CalendarInvitation:
    user_id: str
    ics_uid: str
    raw_attachment: str


@dataclass
class CalendarEvent:
    id: str
    raw_data: dict[str, Any]


class MessageFetcher(ABC):
    @abstractmethod
    def yield_remediated_emails(self) -> Iterator[Message]:
        pass


class EventDeleter(ABC):
    @abstractmethod
    def delete_matching_events(
        self,
        invitation: CalendarInvitation,
        mode: Mode,
        on_event_found_callback: Optional[
            Callable[[CalendarInvitation, CalendarEvent], None]
        ] = None,
    ):
        pass


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
                f"Abnormal Security API key is required. Set {ABNORMAL_API_KEY_ENV_VAR} environment variable or pass it as a constructor argument."
            )
        self.base_url = base_url
        if lookback_minutes is None:
            lookback_minutes_str = os.getenv(LOOKBACK_MINUTES_ENV_VAR)
            try:
                lookback_minutes = int(lookback_minutes_str or DEFAULT_LOOKBACK_MINUTES)
            except ValueError as e:
                raise ValueError(
                    f"{LOOKBACK_MINUTES_ENV_VAR} must be a valid integer, got '{lookback_minutes_str}'"
                ) from e
        self.lookback_minutes = lookback_minutes
        if self.lookback_minutes <= 0:
            raise ValueError(
                f"lookback_minutes must be a positive integer, got {self.lookback_minutes}"
            )
        self.page_size = page_size
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
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
                        f"Rate limited (429) on {method} {url}, retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    continue
                elif response.status_code >= 500:
                    logger.warning(
                        f"Server error ({response.status_code}) on {method} {url}, retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    continue
                response.raise_for_status()
                return response
            except requests.Timeout:
                logger.warning(
                    f"Timeout on {method} {url}, retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                )
                continue
            except requests.ConnectionError as e:
                logger.warning(
                    f"Connection error on {method} {url}: {e}, retrying in {delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})"
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
            "GET", f"{self.base_url}/threats/{threat_id}", timeout=HTTP_TIMEOUT_SECONDS
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


class GoogleWorkspaceEventDeleter(EventDeleter):
    """Deletes calendar events from Google Workspace using Calendar API."""

    def __init__(
        self,
        service_account_file: Optional[str] = None,
        service_account_json: Optional[str] = None,
        access_token: Optional[str] = None,
    ):
        """Initialize with service account credentials or OAuth access token.

        Credentials can be passed directly or read from environment variables:
        - GOOGLE_SERVICE_ACCOUNT_FILE: Path to service account JSON file
        - GOOGLE_SERVICE_ACCOUNT_JSON: Inline service account JSON string
        - GOOGLE_ACCESS_TOKEN: Direct OAuth access token

        For service accounts, requires domain-wide delegation to be enabled
        and calendar.events scope authorized in Google Workspace Admin Console.

        Args:
            service_account_file: Path to service account JSON file
            service_account_json: Inline service account JSON string
            access_token: Direct OAuth access token
        """
        self.service_account_file = service_account_file or os.getenv(
            GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR
        )
        self.service_account_json = service_account_json or os.getenv(
            GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR
        )
        self.access_token = access_token or os.getenv(GOOGLE_ACCESS_TOKEN_ENV_VAR)
        if not any([self.service_account_file, self.service_account_json, self.access_token]):
            raise ValueError(
                f"Google Workspace credentials must be provided via parameters or environment variables ({GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR}, {GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR}, or {GOOGLE_ACCESS_TOKEN_ENV_VAR})"
            )
        self._service_account_creds: Optional[dict] = None
        self._cached_token: Optional[str] = None
        self._cached_token_user: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        if self.service_account_file or self.service_account_json:
            self._load_service_account_credentials()

    def _load_service_account_credentials(self):
        """Load service account credentials from file or JSON string."""
        try:
            if self.service_account_file:
                with open(self.service_account_file) as f:
                    self._service_account_creds = json.load(f)
            elif self.service_account_json:
                self._service_account_creds = json.loads(self.service_account_json)
            if (
                self._service_account_creds is None
                or self._service_account_creds.get("type") != "service_account"
            ):
                raise ValueError("Credentials must be a service account key")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Failed to load service account credentials: {e}") from e

    def _create_jwt(self, user_email: str) -> str:
        """Create a JWT for service account authentication with domain-wide delegation.

        Args:
            user_email: Email address of the user to impersonate

        Returns:
            Signed JWT string

        Raises:
            ValueError: If credentials are invalid
        """
        if self._service_account_creds is None:
            raise ValueError("Service account credentials not loaded")
        now = int(time.time())
        expiry = now + 3600
        payload = {
            "iss": self._service_account_creds["client_email"],
            "sub": user_email,
            "scope": REQUIRED_SCOPE,
            "aud": OAUTH_TOKEN_URL,
            "iat": now,
            "exp": expiry,
        }
        headers = {"alg": "RS256", "typ": "JWT"}
        if "private_key_id" in self._service_account_creds:
            headers["kid"] = self._service_account_creds["private_key_id"]
        private_key = self._service_account_creds["private_key"]
        token: str = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        return token

    def _get_access_token(self, user_email: str) -> str:
        """Get or refresh OAuth access token.

        Args:
            user_email: Email address of the user (for service account impersonation)

        Returns:
            Access token string
        """
        if self.access_token:
            return self.access_token
        now = datetime.now(timezone.utc)
        if (
            self._cached_token
            and self._cached_token_user == user_email
            and self._token_expiry
            and (now < self._token_expiry - timedelta(seconds=TOKEN_EXPIRY_BUFFER_SECONDS))
        ):
            return self._cached_token
        jwt_token = self._create_jwt(user_email)
        response = requests.post(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token,
            },
            timeout=30,
        )
        if response.status_code in (400, 403):
            error_data = response.json()
            error_code = error_data.get("error", "")
            if error_code == "unauthorized_client":
                raise PermissionError(
                    f"Service account is not authorized to impersonate {user_email}. Ensure domain-wide delegation is enabled for this service account and the scope '{REQUIRED_SCOPE}' is authorized in the Google Workspace Admin Console. See: https://support.google.com/a/answer/162106"
                )
        response.raise_for_status()
        token_data = response.json()
        self._cached_token = token_data["access_token"]
        self._cached_token_user = user_email
        expires_in = token_data.get("expires_in", 3600)
        self._token_expiry = now + timedelta(seconds=expires_in)
        return self._cached_token

    def _make_request(
        self, method: str, url: str, user_email: str, params: Optional[dict] = None
    ) -> requests.Response:
        """Make authenticated request to Google Calendar API.

        Args:
            method: HTTP method (GET, DELETE, etc.)
            url: Full URL to request
            user_email: Email address of the user (for service account impersonation)
            params: Optional query parameters

        Returns:
            Response object
        """
        headers = {
            "Authorization": f"Bearer {self._get_access_token(user_email)}",
            "Content-Type": "application/json",
        }
        response = requests.request(method, url, headers=headers, params=params, timeout=60)
        if response.status_code == 403:
            error = response.json().get("error", {})
            error_message = error.get("message", "")
            error_errors = error.get("errors", [])
            for err in error_errors:
                reason = err.get("reason", "")
                if reason in ["insufficientPermissions", "forbidden"]:
                    raise PermissionError(f"Missing calendar.events permission: {REQUIRED_SCOPE}")
            if "insufficient" in error_message.lower() or "permission" in error_message.lower():
                raise PermissionError(f"Missing calendar.events permission: {REQUIRED_SCOPE}")
        return response

    def delete_matching_events(
        self,
        invitation: CalendarInvitation,
        mode: Mode,
        on_event_found_callback: Optional[
            Callable[[CalendarInvitation, CalendarEvent], None]
        ] = None,
    ):
        """Delete calendar events matching the invitation's iCalendar UID.

        Args:
            invitation: CalendarInvitation to process
            mode: Either "dry_run" (log actions but don't delete) or "delete_events"
                (actually delete events).
            on_event_found_callback: Optional callback called when a matching calendar
                event is found. Receives CalendarInvitation and CalendarEvent.
        """
        user_id = invitation.user_id
        ical_uid = invitation.ics_uid
        if mode == MODE_DRY_RUN:
            logger.info(
                f"[DRY RUN] Processing malicious invitation with UID {ical_uid} for user {user_id}"
            )
        url = f"{CALENDAR_API_BASE_URL}/calendars/{CURRENT_USER_CALENDAR_KEYWORD}/events"
        params = {"iCalUID": ical_uid, "showDeleted": "false"}
        events = []
        next_page_token = None
        while True:
            if next_page_token:
                params["pageToken"] = next_page_token
            response = self._make_request("GET", url, user_id, params=params)
            response.raise_for_status()
            response_data = response.json()
            events.extend(response_data.get("items", []))
            next_page_token = response_data.get("nextPageToken")
            if not next_page_token:
                break
        if not events:
            logger.info(f"No events with UID {ical_uid} found for user {user_id}")
            return
        active_events = [e for e in events if e.get("status") != "cancelled"]
        if not active_events:
            logger.info(f"All events with UID {ical_uid} cancelled for user {user_id}")
            return
        for event in active_events:
            event_id = event["id"]
            if on_event_found_callback:
                try:
                    calendar_event = CalendarEvent(id=event_id, raw_data=event)
                    on_event_found_callback(invitation, calendar_event)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")
            if mode == MODE_DRY_RUN:
                logger.info(
                    f"[DRY RUN] Would delete event {event_id} for user {user_id}, UID {ical_uid}"
                )
            else:
                delete_url = f"{CALENDAR_API_BASE_URL}/calendars/{CURRENT_USER_CALENDAR_KEYWORD}/events/{event_id}"
                delete_params = {"sendUpdates": "none"}
                delete_response = self._make_request(
                    "DELETE", delete_url, user_id, params=delete_params
                )
                if delete_response.status_code in (200, 204):
                    logger.info(f"Deleted event {event_id} for user {user_id}, UID {ical_uid}")
                elif delete_response.status_code in (404, 410):
                    logger.warning(f"Event {event_id} already deleted")
                else:
                    delete_response.raise_for_status()


def extract_calendar_invitations(message: Message) -> list[CalendarInvitation]:
    """Extract all iCalendar attachments from an email message as CalendarInvitation objects.

    Deduplicates invitations based on (user_id, ics_uid) pair.
    """
    try:
        email_msg = message_from_string(message.raw)
    except Exception as e:
        logger.error(f"Failed to parse email message for user {message.user_id}: {e}")
        return []
    unique_invitations = {}
    message_header_id = email_msg.get("Message-ID", "<none>")
    for part in email_msg.walk():
        try:
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")
        except Exception as e:
            logger.warning(
                f"Error processing email part for message with Message-ID={message_header_id}: {e}"
            )
            continue
        if not (
            content_type in ["text/calendar", "application/ics"]
            or ("attachment" in content_disposition and ".ics" in content_disposition)
        ):
            continue
        try:
            ics_content = part.get_payload(decode=True)
        except Exception as e:
            logger.warning(
                f"Failed to decode attachment for message with Message-ID={message_header_id}: {e}"
            )
            continue
        if not ics_content:
            continue
        if isinstance(ics_content, bytes):
            ics_content = ics_content.decode("utf-8", errors="ignore")
        elif not isinstance(ics_content, str):
            continue
        raw_attachment = ics_content
        try:
            ics_content_unfolded = re.sub("\\r?\\n[\\t ]", "", ics_content)
            uid_matches = re.findall("UID:([^\\r\\n]+)", ics_content_unfolded)
            for uid in uid_matches:
                invitation_key = (message.user_id, uid)
                if invitation_key not in unique_invitations:
                    unique_invitations[invitation_key] = CalendarInvitation(
                        user_id=message.user_id, ics_uid=uid, raw_attachment=raw_attachment
                    )
        except Exception as e:
            logger.warning(
                f"Failed to extract UID from ICS content for message with Message-ID={message_header_id}: {e}"
            )
            continue
    return list(unique_invitations.values())


def delete_events_from_remediated_emails(
    fetcher: MessageFetcher,
    deleter: EventDeleter,
    mode: Optional[Mode] = None,
    on_invitation_found_callback: Optional[Callable[[CalendarInvitation], None]] = None,
    on_event_found_callback: Optional[Callable[[CalendarInvitation, CalendarEvent], None]] = None,
):
    """Process remediated emails and delete matching calendar events.

    Args:
        fetcher: MessageFetcher instance to retrieve remediated emails
        deleter: EventDeleter instance to delete calendar events
        mode: Either "dry_run" (log actions but don't delete) or "delete_events"
            (actually delete events). Defaults to "dry_run" unless ICS_PHISHING_REMEDIATION_MODE
            env var is set to "delete_events".
        on_invitation_found_callback: Optional callback called when a malicious
            invitation is found. Receives CalendarInvitation.
        on_event_found_callback: Optional callback called when a matching calendar
            event is found. Receives CalendarInvitation and CalendarEvent.
    """
    if mode is None:
        env_value = os.getenv(MODE_ENV_VAR, DEFAULT_MODE)
        if env_value not in VALID_MODES:
            raise ValueError(f"Invalid {MODE_ENV_VAR}={env_value!r}. Must be one of: {VALID_MODES}")
        mode = cast("Mode", env_value)
    for message in fetcher.yield_remediated_emails():
        try:
            invitations = extract_calendar_invitations(message)
        except Exception as e:
            logger.error(f"Error processing message for user {message.user_id}: {e}")
            continue
        for invitation in invitations:
            if on_invitation_found_callback:
                try:
                    on_invitation_found_callback(invitation)
                except Exception as e:
                    logger.error(f"Error in invitation callback: {e}")
            try:
                deleter.delete_matching_events(invitation, mode, on_event_found_callback)
            except Exception as e:
                logger.error(
                    f"Failed to delete event with UID {invitation.ics_uid} for user {invitation.user_id}: {e}"
                )


def main():
    message_fetcher = AbnormalSecurityFetcher()
    event_deleter = GoogleWorkspaceEventDeleter()

    delete_events_from_remediated_emails(message_fetcher, event_deleter)


if __name__ == "__main__":
    main()
