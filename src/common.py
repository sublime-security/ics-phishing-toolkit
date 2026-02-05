"""Common logic and classes for deleting calendar events from remediated emails."""

import logging
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from email import message_from_string
from typing import Any, Callable, Literal, Optional, cast, get_args

logger = logging.getLogger(__name__)

MODE_DRY_RUN = "dry_run"
MODE_DELETE_EVENTS = "delete_events"
VALID_MODES = (MODE_DRY_RUN, MODE_DELETE_EVENTS)
DEFAULT_MODE = MODE_DRY_RUN

Mode = Literal["dry_run", "delete_events"]

assert get_args(Mode) == VALID_MODES

MODE_ENV_VAR = "ICS_PHISHING_REMEDIATION_MODE"


@dataclass
class Message:
    # TODO: support multiple recipients (`user_ids`)
    user_id: str  # email provider user ID or email address
    raw: str


@dataclass
class CalendarInvitation:
    user_id: str
    ics_uid: str
    raw_attachment: str


@dataclass
class CalendarEvent:
    id: str  # Event ID from the calendar provider
    raw_data: dict[str, Any]  # Complete event data from provider API


class MessageFetcher(ABC):
    @abstractmethod
    def yield_remediated_emails(self) -> Iterator[Message]:
        pass


class EventDeleter(ABC):
    # TODO: break delete_matching_events into `find_matching_events` and `delete_event` so that
    #       the common code can manage dry run enforcement and callbacks
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
            # Unfold lines: In ICS format, lines starting with space or tab
            # are continuations of the previous line
            ics_content_unfolded = re.sub(r"\r?\n[\t ]", "", ics_content)

            uid_matches = re.findall(r"UID:([^\r\n]+)", ics_content_unfolded)

            for uid in uid_matches:
                invitation_key = (message.user_id, uid)
                # TODO: in the case of duplicates, include all attachments for a give user/UID pair
                #       on CalendarInvitation (e.g., plural CalendarInvitation.raw_attachments)
                if invitation_key not in unique_invitations:
                    unique_invitations[invitation_key] = CalendarInvitation(
                        user_id=message.user_id, ics_uid=uid, raw_attachment=raw_attachment
                    )
        except Exception as e:
            logger.warning(
                f"Failed to extract UID from ICS content for message"
                f" with Message-ID={message_header_id}: {e}"
            )
            continue

    return list(unique_invitations.values())


# TODO: return summary of deleted events (attachment + mailbox)
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
                    f"Failed to delete event with UID {invitation.ics_uid} "
                    f"for user {invitation.user_id}: {e}"
                )
