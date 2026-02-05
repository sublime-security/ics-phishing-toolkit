import logging
import os
import unittest
from collections.abc import Iterator
from typing import Optional

from emls import generate_eml_with_invite

from common import (
    CalendarInvitation,
    EventDeleter,
    Message,
    MessageFetcher,
    delete_events_from_remediated_emails,
    extract_calendar_invitations,
)

TEST_EML_PATH = os.path.join(os.path.dirname(__file__), "./test_data/two_events_attached.eml")
with open(TEST_EML_PATH, encoding="utf-8") as f:
    TEST_EML = f.read()

TEST_EML_ICALENDAR_UIDS = [
    "040000008200E00075D6C7101B92E00800000000012ADB30CB3FDC01000000000000000010000000D3C9797A1A740C43882F7FE421D7E731",
    "040000008200E00075D6C7101B92E00800000000012ADB30CB3FDC01000000000000000010000000D3C9797A1A739C43882F7FE421C6E713",
]


class MockMessageFetcher(MessageFetcher):
    def __init__(self, messages: list[Message]):
        self.messages = messages

    def yield_remediated_emails(self) -> Iterator[Message]:
        yield from self.messages


class MockEventDeleter(EventDeleter):
    """Mock implementation of EventDeleter that tracks calls."""

    def __init__(self):
        self.deleted_invitations: list[CalendarInvitation] = []

    def delete_matching_events(
        self, invitation: CalendarInvitation, mode, on_event_found_callback=None
    ):
        self.deleted_invitations.append(invitation)


class TestCommon(unittest.TestCase):
    def test_extract_calendar_invitations_two_events(self):
        message = Message(user_id="test@example.com", raw=TEST_EML)

        invitations = extract_calendar_invitations(message)

        self.assertEqual(2, len(invitations))
        for i, invitation in enumerate(invitations):
            self.assertEqual("test@example.com", invitation.user_id)
            self.assertEqual(TEST_EML_ICALENDAR_UIDS[i], invitation.ics_uid)
            self.assertIsNotNone(invitation.raw_attachment)

    def test_extract_calendar_invitations_empty_message(self):
        message = Message(user_id="test@example.com", raw="Subject: Test\n\nNo attachments here.")

        self.assertEqual([], extract_calendar_invitations(message))

    def test_extract_calendar_invitations_deduplicates_by_user_and_uid(self):
        eml_with_duplicate_uids = """From: sender@example.com
To: recipient@example.com
Subject: Meeting Invitation
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Please find calendar invitations attached.

--boundary123
Content-Type: text/calendar; method=REQUEST
Content-Disposition: attachment; filename="invite1.ics"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:duplicate-uid-123
SUMMARY:First Instance
END:VEVENT
END:VCALENDAR

--boundary123
Content-Type: text/calendar; method=REQUEST
Content-Disposition: attachment; filename="invite2.ics"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:duplicate-uid-123
SUMMARY:Second Instance (duplicate)
END:VEVENT
END:VCALENDAR

--boundary123
Content-Type: text/calendar; method=REQUEST
Content-Disposition: attachment; filename="invite3.ics"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:unique-uid-456
SUMMARY:Unique Event
END:VEVENT
END:VCALENDAR

--boundary123--
"""
        message = Message(user_id="test@example.com", raw=eml_with_duplicate_uids)

        invitations = extract_calendar_invitations(message)

        self.assertEqual(2, len(invitations))

        uids = [inv.ics_uid for inv in invitations]
        self.assertIn("duplicate-uid-123", uids)
        self.assertIn("unique-uid-456", uids)

        for invitation in invitations:
            self.assertEqual("test@example.com", invitation.user_id)

    def test_delete_events_from_remediated_emails_with_real_eml(self):
        message = Message(user_id="alice@example.com", raw=TEST_EML)

        fetcher = MockMessageFetcher([message])

        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(2, len(deleter.deleted_invitations))

        for i, invitation in enumerate(deleter.deleted_invitations):
            self.assertEqual("alice@example.com", invitation.user_id)
            self.assertEqual(TEST_EML_ICALENDAR_UIDS[i], invitation.ics_uid)

    def test_delete_events_from_remediated_emails_multiple_users(self):
        messages = [
            Message(
                user_id="user1@example.com",
                raw=generate_eml_with_invite("user1@example.com", "uid-001"),
            ),
            Message(
                user_id="user2@example.com",
                raw=generate_eml_with_invite("user2@example.com", "uid-002"),
            ),
            Message(
                user_id="user3@example.com",
                raw=generate_eml_with_invite("user3@example.com", "uid-003"),
            ),
            Message(
                user_id="user3@example.com",
                raw=generate_eml_with_invite("user3@example.com", "uid-004"),
            ),
        ]

        fetcher = MockMessageFetcher(messages)
        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        expected_data = [
            ("user1@example.com", "uid-001"),
            ("user2@example.com", "uid-002"),
            ("user3@example.com", "uid-003"),
            ("user3@example.com", "uid-004"),
        ]

        self.assertEqual(len(expected_data), len(deleter.deleted_invitations))

        for i, invitation in enumerate(deleter.deleted_invitations):
            (expected_user, expected_uid) = expected_data[i]
            self.assertEqual(expected_user, invitation.user_id)
            self.assertEqual(expected_uid, invitation.ics_uid)

    def test_delete_events_from_remediated_emails_no_messages(self):
        fetcher = MockMessageFetcher([])
        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(0, len(deleter.deleted_invitations))

    def test_delete_events_from_remediated_emails_message_without_event(self):
        messages = [
            Message(user_id="user1@example.com", raw="Subject: No calendar\n\nJust text."),
            Message(user_id="user2@example.com", raw="Subject: Also no calendar\n\nMore text."),
        ]

        fetcher = MockMessageFetcher(messages)
        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(0, len(deleter.deleted_invitations))

    def test_delete_events_from_remediated_emails_with_and_without_event(self):
        messages = [
            Message(user_id="user1@example.com", raw="Subject: No calendar\n\nJust text."),
            Message(
                user_id="user2@example.com",
                raw=generate_eml_with_invite("user2@example.com", "uid-001"),
            ),
        ]

        fetcher = MockMessageFetcher(messages)
        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(1, len(deleter.deleted_invitations))
        self.assertEqual("uid-001", deleter.deleted_invitations[0].ics_uid)


class MockEventDeleterWithErrors(EventDeleter):
    """Mock deleter that raises exceptions for specific UIDs."""

    def __init__(self, uids_to_fail: Optional[set[str]] = None):
        self.uids_to_fail = uids_to_fail or set()
        self.deleted_invitations: list[CalendarInvitation] = []
        self.failed_invitations: list[CalendarInvitation] = []

    def delete_matching_events(
        self, invitation: CalendarInvitation, mode, on_event_found_callback=None
    ):
        if invitation.ics_uid in self.uids_to_fail:
            self.failed_invitations.append(invitation)
            raise Exception(f"Simulated deletion failure for {invitation.ics_uid}")
        self.deleted_invitations.append(invitation)


class TestErrorHandling(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_extract_calendar_invitations_malformed_email(self):
        message = Message(user_id="test@example.com", raw="\x00\x01\x02invalid binary data")

        invitations = extract_calendar_invitations(message)

        self.assertEqual([], invitations)

    def test_extract_calendar_invitations_empty_raw(self):
        message = Message(user_id="test@example.com", raw="")

        invitations = extract_calendar_invitations(message)

        self.assertEqual([], invitations)

    def test_delete_events_continues_on_deletion_error(self):
        messages = [
            Message(
                user_id="user1@example.com",
                raw=generate_eml_with_invite("user1@example.com", "uid-001"),
            ),
            Message(
                user_id="user2@example.com",
                raw=generate_eml_with_invite("user2@example.com", "uid-002"),
            ),
            Message(
                user_id="user3@example.com",
                raw=generate_eml_with_invite("user3@example.com", "uid-003"),
            ),
        ]

        fetcher = MockMessageFetcher(messages)
        deleter = MockEventDeleterWithErrors(uids_to_fail={"uid-002"})

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(2, len(deleter.deleted_invitations))
        self.assertEqual(1, len(deleter.failed_invitations))
        self.assertEqual("uid-001", deleter.deleted_invitations[0].ics_uid)
        self.assertEqual("uid-003", deleter.deleted_invitations[1].ics_uid)
        self.assertEqual("uid-002", deleter.failed_invitations[0].ics_uid)

    def test_delete_events_with_mix_of_valid_and_malformed_messages(self):
        messages = [
            Message(user_id="user1@example.com", raw="\x00invalid"),
            Message(
                user_id="user2@example.com",
                raw=generate_eml_with_invite("user2@example.com", "uid-002"),
            ),
            Message(user_id="user3@example.com", raw="Subject: No calendar\n\nText only."),
            Message(
                user_id="user4@example.com",
                raw=generate_eml_with_invite("user4@example.com", "uid-004"),
            ),
        ]

        fetcher = MockMessageFetcher(messages)
        deleter = MockEventDeleter()

        delete_events_from_remediated_emails(fetcher, deleter)

        self.assertEqual(2, len(deleter.deleted_invitations))
        self.assertEqual("uid-002", deleter.deleted_invitations[0].ics_uid)
        self.assertEqual("uid-004", deleter.deleted_invitations[1].ics_uid)
