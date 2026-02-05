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

PROOFPOINT_CLIENT_ID_ENV_VAR = "PROOFPOINT_CLIENT_ID"
PROOFPOINT_CLIENT_SECRET_ENV_VAR = "PROOFPOINT_CLIENT_SECRET"
LOOKBACK_MINUTES_ENV_VAR = "MESSAGE_LOOKBACK_MINUTES"
GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_FILE"
GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_JSON"
GOOGLE_ACCESS_TOKEN_ENV_VAR = "GOOGLE_ACCESS_TOKEN"
MODE_ENV_VAR = "ICS_PHISHING_REMEDIATION_MODE"

TOKEN_BASE_URL = "https://auth.proofpoint.com/v1/token"
API_BASE_URL = "https://threatprotection-api.proofpoint.com"
HTTP_TIMEOUT_SECONDS = 60
DEFAULT_LOOKBACK_MINUTES = 5
TOKEN_EXPIRY_BUFFER_SECONDS = 300
FETCH_IN_PROGRESS_SLEEP_SECONDS = 5
THROTTLED_SLEEP_SECONDS = 30
POLLING_TIMEOUT_SECONDS = 180
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
                f"Proofpoint credentials are required. Set {PROOFPOINT_CLIENT_ID_ENV_VAR} and {PROOFPOINT_CLIENT_SECRET_ENV_VAR} environment variables or pass them as constructor arguments."
            )
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
                    f"Timeout exceeded ({POLLING_TIMEOUT_SECONDS}s) while waiting for message {message_id}"
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
                    f"Message {message_id} fetch in progress, waiting {FETCH_IN_PROGRESS_SLEEP_SECONDS}s"
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
    message_fetcher = ProofpointCloudFetcher()
    event_deleter = GoogleWorkspaceEventDeleter()

    delete_events_from_remediated_emails(message_fetcher, event_deleter)


if __name__ == "__main__":
    main()
