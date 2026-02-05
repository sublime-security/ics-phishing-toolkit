import logging
import os
import unittest
from urllib.parse import parse_qs, urlparse

import responses

from calendar_providers.microsoft365 import Microsoft365EventDeleter
from common import CalendarInvitation


class TestMicrosoft365EventDeleter(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.client_id = "test-client-id"
        self.client_secret = "test-client-secret"
        self.tenant_id = "test-tenant-id"
        for var in [
            "MICROSOFT_CLIENT_ID",
            "MICROSOFT_CLIENT_SECRET",
            "MICROSOFT_TENANT_ID",
        ]:
            os.environ.pop(var, None)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        for var in [
            "MICROSOFT_CLIENT_ID",
            "MICROSOFT_CLIENT_SECRET",
            "MICROSOFT_TENANT_ID",
        ]:
            os.environ.pop(var, None)

    def test_init_with_parameters(self):
        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        self.assertEqual(self.client_id, deleter.client_id)
        self.assertEqual(self.client_secret, deleter.client_secret)
        self.assertEqual(self.tenant_id, deleter.tenant_id)

    def test_init_with_environment_variables(self):
        os.environ["MICROSOFT_CLIENT_ID"] = self.client_id
        os.environ["MICROSOFT_CLIENT_SECRET"] = self.client_secret
        os.environ["MICROSOFT_TENANT_ID"] = self.tenant_id

        deleter = Microsoft365EventDeleter()

        self.assertEqual(self.client_id, deleter.client_id)
        self.assertEqual(self.client_secret, deleter.client_secret)
        self.assertEqual(self.tenant_id, deleter.tenant_id)

    def test_init_missing_credentials_raises_error(self):
        with self.assertRaises(ValueError) as context:
            Microsoft365EventDeleter()

        self.assertIn("credentials must be provided", str(context.exception).lower())

    @responses.activate
    def test_get_access_token_success(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token-123", "expires_in": 3600},
            status=200,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        token = deleter._get_access_token()

        self.assertEqual("test-token-123", token)
        self.assertEqual(1, len(responses.calls))

    @responses.activate
    def test_get_access_token_caching(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "cached-token", "expires_in": 3600},
            status=200,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        deleter._get_access_token()
        token2 = deleter._get_access_token()

        self.assertEqual("cached-token", token2)
        self.assertEqual(1, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_success(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={
                "value": [
                    {"id": "event-1", "isCancelled": False},
                    {"id": "event-2", "isCancelled": False},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-1",
            status=204,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-2",
            status=204,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(4, len(responses.calls))

        # Verify filter query parameter
        get_request = responses.calls[1]
        self.assertEqual("GET", get_request.request.method)
        assert get_request.request.url is not None
        parsed_url = urlparse(get_request.request.url)
        params = parse_qs(parsed_url.query)
        self.assertIn("$filter", params)
        self.assertEqual("iCalUId eq 'test-uid-123'", params["$filter"][0])

        # Verify Authorization header
        self.assertEqual("Bearer test-token", get_request.request.headers["Authorization"])

        delete_request_1 = responses.calls[2]
        self.assertEqual("DELETE", delete_request_1.request.method)
        self.assertEqual("Bearer test-token", delete_request_1.request.headers["Authorization"])

        delete_request_2 = responses.calls[3]
        self.assertEqual("DELETE", delete_request_2.request.method)
        self.assertEqual("Bearer test-token", delete_request_2.request.headers["Authorization"])

    @responses.activate
    def test_delete_matching_events_no_events_found(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={"value": []},
            status=200,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="nonexistent-uid",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="dry_run")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_skips_cancelled(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={
                "value": [
                    {"id": "event-1", "isCancelled": True},
                    {"id": "event-2", "isCancelled": False},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-2",
            status=204,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(3, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_already_deleted(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={"value": [{"id": "event-1", "isCancelled": False}]},
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-1",
            status=404,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(3, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_permission_error(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={"error": {"code": "ErrorAccessDenied", "message": "Access denied"}},
            status=403,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        with self.assertRaises(PermissionError) as context:
            deleter.delete_matching_events(invitation, mode="dry_run")

        self.assertIn("Calendars.ReadWrite", str(context.exception))

    @responses.activate
    def test_delete_matching_events_pagination(self):
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={
                "value": [
                    {"id": "event-1", "isCancelled": False},
                    {"id": "event-2", "isCancelled": False},
                ],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events?$skiptoken=abc123",
            },
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events?$skiptoken=abc123",
            json={
                "value": [
                    {"id": "event-3", "isCancelled": False},
                ]
                # no nextLink
            },
            status=200,
        )

        for event_id in ["event-1", "event-2", "event-3"]:
            responses.add(
                responses.DELETE,
                f"https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/{event_id}",
                status=204,
            )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(6, len(responses.calls))

        delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
        self.assertEqual(3, len(delete_calls))

    @responses.activate
    def test_dry_run_mode_does_not_delete(self):
        """Test that dry run mode queries events but does not delete them."""
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={
                "value": [
                    {"id": "event-1", "isCancelled": False},
                    {"id": "event-2", "isCancelled": False},
                ]
            },
            status=200,
        )

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="dry_run")

        # Should only have token request and GET request, no DELETE
        self.assertEqual(2, len(responses.calls))
        delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
        self.assertEqual(0, len(delete_calls))

    @responses.activate
    def test_event_callback_is_called(self):
        """Test that the event callback is invoked for each matching event."""
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={
                "value": [
                    {"id": "event-1", "isCancelled": False},
                    {"id": "event-2", "isCancelled": False},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-1",
            status=204,
        )

        responses.add(
            responses.DELETE,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events/event-2",
            status=204,
        )

        callback_events = []

        def event_callback(invitation, calendar_event):
            callback_events.append(calendar_event)

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(
            invitation, mode="delete_events", on_event_found_callback=event_callback
        )

        self.assertEqual(2, len(callback_events))
        self.assertEqual("event-1", callback_events[0].id)
        self.assertEqual("event-1", callback_events[0].raw_data["id"])
        self.assertEqual("event-2", callback_events[1].id)
        self.assertEqual("event-2", callback_events[1].raw_data["id"])

    @responses.activate
    def test_dry_run_with_callbacks(self):
        """Test that dry run mode works correctly with event callbacks."""
        responses.add(
            responses.POST,
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://graph.microsoft.com/v1.0/users/user@example.com/calendar/events",
            json={"value": [{"id": "event-1", "isCancelled": False}]},
            status=200,
        )

        event_called = []

        def event_callback(invitation, calendar_event):
            event_called.append(calendar_event)

        deleter = Microsoft365EventDeleter(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(
            invitation, mode="dry_run", on_event_found_callback=event_callback
        )

        # Event callback should be called even in dry run mode
        self.assertEqual(1, len(event_called))

        # But no DELETE requests should be made
        delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
        self.assertEqual(0, len(delete_calls))
