import json
import logging
import os
import unittest
from urllib.parse import parse_qs, urlparse

import responses

from calendar_providers.google_workspace import GoogleWorkspaceEventDeleter
from common import CalendarInvitation


class TestGoogleWorkspaceEventDeleter(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.access_token = "test-access-token"
        self.service_account_creds = {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "test-key-id",
            # private key of course generated specifically for this test
            "private_key": """-----BEGIN PRIVATE KEY-----
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
rdEOXJYomaZZFa8q89TCDB3FMMBX
-----END PRIVATE KEY-----""",
            "client_email": "test-sa@test-project.iam.gserviceaccount.com",
            "client_id": "123456789",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }

        for var in [
            "GOOGLE_SERVICE_ACCOUNT_FILE",
            "GOOGLE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_ACCESS_TOKEN",
        ]:
            os.environ.pop(var, None)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        for var in [
            "GOOGLE_SERVICE_ACCOUNT_FILE",
            "GOOGLE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_ACCESS_TOKEN",
        ]:
            os.environ.pop(var, None)

    def test_init_with_access_token(self):
        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        self.assertEqual(self.access_token, deleter.access_token)
        self.assertIsNone(deleter.service_account_file)
        self.assertIsNone(deleter.service_account_json)

    def test_init_with_service_account_json(self):
        sa_json = json.dumps(self.service_account_creds)
        deleter = GoogleWorkspaceEventDeleter(service_account_json=sa_json)

        self.assertEqual(sa_json, deleter.service_account_json)
        self.assertIsNotNone(deleter._service_account_creds)
        assert deleter._service_account_creds is not None
        self.assertEqual("service_account", deleter._service_account_creds["type"])

    def test_init_with_environment_variables(self):
        os.environ["GOOGLE_ACCESS_TOKEN"] = self.access_token

        deleter = GoogleWorkspaceEventDeleter()

        self.assertEqual(self.access_token, deleter.access_token)

    @responses.activate
    def test_credentials_from_environment_variables(self):
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "test-token-from-env", "expires_in": 3600},
            status=200,
        )

        os.environ["GOOGLE_SERVICE_ACCOUNT_JSON"] = json.dumps(self.service_account_creds)

        deleter = GoogleWorkspaceEventDeleter()

        self.assertEqual(json.dumps(self.service_account_creds), deleter.service_account_json)
        self.assertIsNotNone(deleter._service_account_creds)
        self.assertEqual("service_account", deleter._service_account_creds["type"])

        token = deleter._get_access_token("user@example.com")
        self.assertEqual("test-token-from-env", token)

    def test_init_missing_credentials_raises_error(self):
        with self.assertRaises(ValueError) as context:
            GoogleWorkspaceEventDeleter()

        self.assertIn("credentials must be provided", str(context.exception).lower())

    def test_init_with_invalid_service_account_json(self):
        with self.assertRaises(ValueError) as context:
            GoogleWorkspaceEventDeleter(service_account_json="not valid json")

        self.assertIn("failed to load", str(context.exception).lower())

    def test_init_with_non_service_account_json(self):
        invalid_creds = {"type": "authorized_user", "client_id": "test"}

        with self.assertRaises(ValueError) as context:
            GoogleWorkspaceEventDeleter(service_account_json=json.dumps(invalid_creds))

        self.assertIn("service account", str(context.exception).lower())

    @responses.activate
    def test_get_access_token_with_service_account(self):
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "test-token-123", "expires_in": 3600},
            status=200,
        )

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
        )

        token = deleter._get_access_token("user@example.com")

        self.assertEqual("test-token-123", token)
        self.assertEqual(1, len(responses.calls))

    @responses.activate
    def test_get_access_token_caching(self):
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "cached-token", "expires_in": 3600},
            status=200,
        )

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
        )

        deleter._get_access_token("user@example.com")
        token2 = deleter._get_access_token("user@example.com")

        self.assertEqual("cached-token", token2)
        self.assertEqual(1, len(responses.calls))

    @responses.activate
    def test_get_access_token_not_cached_across_users(self):
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "token-user1", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "token-user2", "expires_in": 3600},
            status=200,
        )

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
        )

        token1 = deleter._get_access_token("user1@example.com")
        token2 = deleter._get_access_token("user2@example.com")

        self.assertEqual("token-user1", token1)
        self.assertEqual("token-user2", token2)
        self.assertEqual(2, len(responses.calls))

    @responses.activate
    def test_get_access_token_unauthorized_client_error(self):
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={
                "error": "unauthorized_client",
                "error_description": "Client is unauthorized to retrieve"
                " access tokens using this method.",
            },
            status=403,
        )

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
        )

        with self.assertRaises(PermissionError) as context:
            deleter._get_access_token("user@example.com")

        error_message = str(context.exception)
        self.assertIn("not authorized to impersonate", error_message)
        self.assertIn("domain-wide delegation", error_message)
        self.assertIn("user@example.com", error_message)
        self.assertIn("https://support.google.com/a/answer/162106", error_message)

    @responses.activate
    def test_delete_matching_events_success(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "items": [
                    {"id": "event-1", "status": "confirmed"},
                    {"id": "event-2", "status": "confirmed"},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-1",
            status=204,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-2",
            status=204,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(3, len(responses.calls))

        get_request = responses.calls[0]
        self.assertEqual("GET", get_request.request.method)
        assert get_request.request.url is not None
        parsed_url = urlparse(get_request.request.url)
        params = parse_qs(parsed_url.query)
        self.assertEqual("test-uid-123", params["iCalUID"][0])
        self.assertEqual("false", params["showDeleted"][0])

        self.assertEqual(
            f"Bearer {self.access_token}", get_request.request.headers["Authorization"]
        )

        delete_request_1 = responses.calls[1]
        self.assertEqual("DELETE", delete_request_1.request.method)
        assert delete_request_1.request.url is not None
        parsed_url = urlparse(delete_request_1.request.url)
        params = parse_qs(parsed_url.query)
        self.assertEqual("none", params["sendUpdates"][0])
        self.assertEqual(
            f"Bearer {self.access_token}", delete_request_1.request.headers["Authorization"]
        )

        delete_request_2 = responses.calls[2]
        self.assertEqual("DELETE", delete_request_2.request.method)
        assert delete_request_2.request.url is not None
        parsed_url = urlparse(delete_request_2.request.url)
        params = parse_qs(parsed_url.query)
        self.assertEqual("none", params["sendUpdates"][0])

    @responses.activate
    def test_delete_matching_events_no_events_found(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={"items": []},
            status=200,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="nonexistent-uid",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="dry_run")

        self.assertEqual(1, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_skips_cancelled(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "items": [
                    {"id": "event-1", "status": "cancelled"},
                    {"id": "event-2", "status": "confirmed"},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-2",
            status=204,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_already_deleted_404(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={"items": [{"id": "event-1", "status": "confirmed"}]},
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-1",
            status=404,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_already_deleted_410(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={"items": [{"id": "event-1", "status": "confirmed"}]},
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-1",
            status=410,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    def test_delete_matching_events_permission_error(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "error": {
                    "code": 403,
                    "message": "Insufficient Permission",
                    "errors": [{"reason": "insufficientPermissions"}],
                }
            },
            status=403,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        with self.assertRaises(PermissionError) as context:
            deleter.delete_matching_events(invitation, mode="dry_run")

        self.assertIn("calendar.events", str(context.exception))

    @responses.activate
    def test_delete_matching_events_with_pagination(self):
        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "items": [{"id": "event-1", "status": "confirmed"}],
                "nextPageToken": "page2token",
            },
            status=200,
        )

        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={"items": [{"id": "event-2", "status": "confirmed"}]},
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-1",
            status=204,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-2",
            status=204,
        )

        deleter = GoogleWorkspaceEventDeleter(access_token=self.access_token)

        invitation = CalendarInvitation(
            user_id="user@example.com",
            ics_uid="test-uid-123",
            raw_attachment="raw-ics-content",
        )

        deleter.delete_matching_events(invitation, mode="delete_events")

        self.assertEqual(4, len(responses.calls))

        get_calls = [c for c in responses.calls if c.request.method == "GET"]
        self.assertEqual(2, len(get_calls))
        assert get_calls[1].request.url is not None
        parsed_url = urlparse(get_calls[1].request.url)
        params = parse_qs(parsed_url.query)
        self.assertEqual("page2token", params.get("pageToken", [None])[0])

        delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
        self.assertEqual(2, len(delete_calls))

    @responses.activate
    def test_dry_run_mode_does_not_delete(self):
        """Test that dry run mode queries events but does not delete them."""
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "items": [
                    {"id": "event-1", "status": "confirmed"},
                    {"id": "event-2", "status": "confirmed"},
                ]
            },
            status=200,
        )

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
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
            "https://oauth2.googleapis.com/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={
                "items": [
                    {"id": "event-1", "status": "confirmed"},
                    {"id": "event-2", "status": "confirmed"},
                ]
            },
            status=200,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-1",
            status=204,
        )

        responses.add(
            responses.DELETE,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events/event-2",
            status=204,
        )

        callback_events = []

        def event_callback(invitation, calendar_event):
            callback_events.append(calendar_event)

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
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
            "https://oauth2.googleapis.com/token",
            json={"access_token": "test-token", "expires_in": 3600},
            status=200,
        )

        responses.add(
            responses.GET,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json={"items": [{"id": "event-1", "status": "confirmed"}]},
            status=200,
        )

        event_called = []

        def event_callback(invitation, calendar_event):
            event_called.append(calendar_event)

        deleter = GoogleWorkspaceEventDeleter(
            service_account_json=json.dumps(self.service_account_creds)
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
