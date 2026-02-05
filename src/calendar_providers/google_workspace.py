"""Google Workspace calendar event deletion using Google Calendar API."""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import jwt
import requests

from common import MODE_DRY_RUN, CalendarEvent, CalendarInvitation, EventDeleter, Mode

logger = logging.getLogger(__name__)

GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_FILE"
GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR = "GOOGLE_SERVICE_ACCOUNT_JSON"
GOOGLE_ACCESS_TOKEN_ENV_VAR = "GOOGLE_ACCESS_TOKEN"

TOKEN_EXPIRY_BUFFER_SECONDS = 300
CALENDAR_API_BASE_URL = "https://www.googleapis.com/calendar/v3"
CURRENT_USER_CALENDAR_KEYWORD = "primary"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/calendar.events"


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
                "Google Workspace credentials must be provided via parameters "
                "or environment variables "
                f"({GOOGLE_SERVICE_ACCOUNT_FILE_ENV_VAR}, {GOOGLE_SERVICE_ACCOUNT_JSON_ENV_VAR}, "
                f"or {GOOGLE_ACCESS_TOKEN_ENV_VAR})"
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

        headers = {
            "alg": "RS256",
            "typ": "JWT",
        }

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
            and now < (self._token_expiry - timedelta(seconds=TOKEN_EXPIRY_BUFFER_SECONDS))
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
                    f"Service account is not authorized to impersonate {user_email}. "
                    "Ensure domain-wide delegation is enabled for this service account "
                    f"and the scope '{REQUIRED_SCOPE}' is authorized in the "
                    "Google Workspace Admin Console. "
                    "See: https://support.google.com/a/answer/162106"
                )

        response.raise_for_status()

        token_data = response.json()
        self._cached_token = token_data["access_token"]
        self._cached_token_user = user_email
        expires_in = token_data.get("expires_in", 3600)
        self._token_expiry = now + timedelta(seconds=expires_in)

        return self._cached_token

    def _make_request(
        self,
        method: str,
        url: str,
        user_email: str,
        params: Optional[dict] = None,
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
        params = {
            "iCalUID": ical_uid,
            "showDeleted": "false",
        }

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
                delete_url = (
                    f"{CALENDAR_API_BASE_URL}"
                    f"/calendars/{CURRENT_USER_CALENDAR_KEYWORD}/events/{event_id}"
                )
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
