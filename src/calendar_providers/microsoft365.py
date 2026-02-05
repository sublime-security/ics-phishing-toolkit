"""Microsoft 365 calendar event deletion using Microsoft Graph API."""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import requests

from common import MODE_DRY_RUN, CalendarEvent, CalendarInvitation, EventDeleter, Mode

logger = logging.getLogger(__name__)

MICROSOFT_CLIENT_ID_ENV_VAR = "MICROSOFT_CLIENT_ID"
MICROSOFT_CLIENT_SECRET_ENV_VAR = "MICROSOFT_CLIENT_SECRET"
MICROSOFT_TENANT_ID_ENV_VAR = "MICROSOFT_TENANT_ID"

TOKEN_EXPIRY_BUFFER_SECONDS = 300
GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class Microsoft365EventDeleter(EventDeleter):
    """Deletes calendar events from Microsoft 365 using Graph API."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ):
        """Initialize with OAuth client credentials for app-only access.

        Credentials can be passed directly or read from environment variables:
        - MICROSOFT_CLIENT_ID
        - MICROSOFT_CLIENT_SECRET
        - MICROSOFT_TENANT_ID

        Requires Calendars.ReadWrite application permission in Azure AD.

        Args:
            client_id: Microsoft OAuth client ID
            client_secret: Microsoft OAuth client secret
            tenant_id: Microsoft tenant ID
        """

        self.client_id = client_id or os.getenv(MICROSOFT_CLIENT_ID_ENV_VAR)
        self.client_secret = client_secret or os.getenv(MICROSOFT_CLIENT_SECRET_ENV_VAR)
        self.tenant_id = tenant_id or os.getenv(MICROSOFT_TENANT_ID_ENV_VAR)

        if not all([self.client_id, self.client_secret, self.tenant_id]):
            raise ValueError(
                "Microsoft 365 credentials must be provided via parameters "
                f"or environment variables ({MICROSOFT_CLIENT_ID_ENV_VAR}, "
                f"{MICROSOFT_CLIENT_SECRET_ENV_VAR}, {MICROSOFT_TENANT_ID_ENV_VAR})"
            )

        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def _get_access_token(self) -> str:
        """Get or refresh OAuth access token using client credentials flow."""
        now = datetime.now(timezone.utc)
        if (
            self._token
            and self._token_expiry
            and now < (self._token_expiry - timedelta(seconds=TOKEN_EXPIRY_BUFFER_SECONDS))
        ):
            return self._token

        response = requests.post(
            TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id),
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        response.raise_for_status()

        token_data = response.json()
        self._token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        self._token_expiry = now + timedelta(seconds=expires_in)

        return self._token

    def _make_request(
        self, method: str, url: str, params: Optional[dict] = None
    ) -> requests.Response:
        """Make authenticated request to Microsoft Graph API."""
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

        response = requests.request(method, url, headers=headers, params=params, timeout=60)

        if response.status_code == 403:
            error = response.json().get("error", {})
            if "AccessDenied" in error.get("code", ""):
                raise PermissionError("Missing Calendars.ReadWrite permission")

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

        url = f"{GRAPH_API_BASE_URL}/users/{user_id}/calendar/events"
        filter_query = f"iCalUId eq '{ical_uid}'"

        events = []
        next_url = url
        params = {"$filter": filter_query}

        while next_url:
            response = self._make_request(
                "GET", next_url, params=params if next_url == url else None
            )
            response.raise_for_status()

            response_data = response.json()
            events.extend(response_data.get("value", []))

            next_url = response_data.get("@odata.nextLink")

        if not events:
            logger.info(f"No events with UID {ical_uid} found for user {user_id}")
            return

        active_events = [e for e in events if not e.get("isCancelled", False)]

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
                delete_url = f"{GRAPH_API_BASE_URL}/users/{user_id}/calendar/events/{event_id}"

                delete_response = self._make_request("DELETE", delete_url)

                if delete_response.status_code in (200, 204):
                    logger.info(f"Deleted event {event_id} for user {user_id}, UID {ical_uid}")
                elif delete_response.status_code == 404:
                    logger.warning(f"Event {event_id} already deleted")
                else:
                    delete_response.raise_for_status()
