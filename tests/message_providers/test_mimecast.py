import json
import logging
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests
import responses

from message_providers.mimecast import (
    API_BASE_URLS,
    ARCHIVE_SEARCH_REASON,
    OAUTH_TOKEN_URLS,
    MimecastFetcher,
)


class TestMimecastFetcher(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        # Patch time.sleep to prevent actual delays in tests
        self.sleep_patcher = patch("message_providers.mimecast.time.sleep")
        self.mock_sleep = self.sleep_patcher.start()

        for var in [
            "MIMECAST_CLIENT_ID",
            "MIMECAST_CLIENT_SECRET",
            "MIMECAST_REGION",
            "MESSAGE_LOOKBACK_MINUTES",
        ]:
            os.environ.pop(var, None)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        self.sleep_patcher.stop()

        for var in [
            "MIMECAST_CLIENT_ID",
            "MIMECAST_CLIENT_SECRET",
            "MIMECAST_REGION",
            "MESSAGE_LOOKBACK_MINUTES",
        ]:
            os.environ.pop(var, None)

    def get_mock_credentials(self):
        return {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
        }

    def get_mock_token_response(self):
        return {
            "access_token": "mock_access_token_12345",
            "token_type": "Bearer",
            "expires_in": 1800,  # 30 minutes
        }

    def get_mock_incidents_response(self):
        return {
            "data": [
                {
                    "incidents": [
                        {
                            "code": "TR-0001-00001-A",
                            "type": "automatic",
                            "searchCriteria": {
                                "messageId": "<msg1@example.com>",
                                "to": "user1@example.com",
                                "from": "sender@malicious.com",
                            },
                        },
                        {
                            "code": "TR-0001-00002-B",
                            "type": "manual",
                            "searchCriteria": {
                                "messageId": "<msg2@example.com>",
                                "to": "user2@example.com",
                                "from": "phisher@bad.com",
                            },
                        },
                        {
                            "code": "TR-0001-00003-C",
                            "type": "automatic",
                            "searchCriteria": {
                                "messageId": "<msg3@example.com>",
                                # Missing 'to' field
                                "from": "spammer@evil.com",
                            },
                        },
                    ]
                }
            ]
        }

    def get_mock_archive_search_response(self, archive_id="arch123"):
        return {"data": [{"trackedEmails": [{"id": archive_id, "subject": "Test Subject"}]}]}

    def mock_oauth_token(self, region="global"):
        responses.post(
            OAUTH_TOKEN_URLS[region],
            json=self.get_mock_token_response(),
            status=200,
        )

    # Credential and Initialization Tests

    @responses.activate
    def test_missing_credentials_raises_error(self):
        with self.assertRaises(ValueError) as context:
            MimecastFetcher(
                client_id="",
                client_secret="",
            )
        self.assertIn("credentials are required", str(context.exception))

    @responses.activate
    def test_missing_client_id_raises_error(self):
        with self.assertRaises(ValueError):
            MimecastFetcher(
                client_id="",
                client_secret="secret",
            )

    @responses.activate
    def test_invalid_region_raises_error(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        with self.assertRaises(ValueError) as context:
            MimecastFetcher(**creds, region="invalid_region")
        self.assertIn("Invalid region", str(context.exception))

    @responses.activate
    def test_init_with_default_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        fetcher = MimecastFetcher(**creds)
        self.assertEqual(fetcher.lookback_minutes, 5)

    @responses.activate
    def test_init_with_custom_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        fetcher = MimecastFetcher(**creds, lookback_minutes=720)
        self.assertEqual(fetcher.lookback_minutes, 720)

    @responses.activate
    def test_init_with_env_var_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "2880"
        fetcher = MimecastFetcher(**creds)
        self.assertEqual(fetcher.lookback_minutes, 2880)

    @responses.activate
    def test_init_with_invalid_env_var_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "invalid"
        with self.assertRaises(ValueError) as context:
            MimecastFetcher(**creds)
        self.assertIn("must be a valid integer", str(context.exception))
        self.assertIn("invalid", str(context.exception))

    @responses.activate
    def test_init_with_negative_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        with self.assertRaises(ValueError) as context:
            MimecastFetcher(**creds, lookback_minutes=-10)
        self.assertIn("must be a positive integer", str(context.exception))

    @responses.activate
    def test_init_with_zero_env_var_lookback_minutes(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "0"
        with self.assertRaises(ValueError) as context:
            MimecastFetcher(**creds)
        self.assertIn("must be a positive integer", str(context.exception))

    # Authentication Tests

    @responses.activate
    def test_oauth_token_acquisition(self):
        creds = self.get_mock_credentials()

        responses.post(
            OAUTH_TOKEN_URLS["global"],
            json=self.get_mock_token_response(),
            status=200,
        )

        fetcher = MimecastFetcher(**creds)

        self.assertEqual(fetcher._access_token, "mock_access_token_12345")
        self.assertIsNotNone(fetcher._token_expires_at)

        self.assertEqual(fetcher.session.headers["Authorization"], "Bearer mock_access_token_12345")

        oauth_request = responses.calls[0].request
        self.assertEqual(oauth_request.headers["Content-Type"], "application/x-www-form-urlencoded")
        # Body is urlencoded, so check the body string
        body = oauth_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        self.assertIn("grant_type=client_credentials", body)
        self.assertIn("client_id=test_client_id", body)
        self.assertIn("client_secret=test_client_secret", body)

    @responses.activate
    def test_credentials_from_environment_variables(self):
        responses.post(
            OAUTH_TOKEN_URLS["global"],
            json=self.get_mock_token_response(),
            status=200,
        )

        os.environ["MIMECAST_CLIENT_ID"] = "test_client_id"
        os.environ["MIMECAST_CLIENT_SECRET"] = "test_client_secret"
        os.environ["MIMECAST_REGION"] = "global"

        fetcher = MimecastFetcher()

        self.assertEqual(fetcher.client_id, "test_client_id")
        self.assertEqual(fetcher.client_secret, "test_client_secret")
        self.assertEqual(fetcher._access_token, "mock_access_token_12345")
        self.assertEqual(fetcher.session.headers["Authorization"], "Bearer mock_access_token_12345")

    @responses.activate
    def test_oauth_token_refresh(self):
        creds = self.get_mock_credentials()

        # initial token acquisition
        responses.post(
            OAUTH_TOKEN_URLS["global"],
            json=self.get_mock_token_response(),
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        initial_token = fetcher._access_token

        # refresh with a different token
        responses.post(
            OAUTH_TOKEN_URLS["global"],
            json={
                "access_token": "refreshed_token_67890",
                "token_type": "Bearer",
                "expires_in": 1800,
            },
            status=200,
        )

        fetcher._refresh_access_token()

        self.assertEqual(fetcher._access_token, "refreshed_token_67890")
        self.assertNotEqual(fetcher._access_token, initial_token)

        refresh_request = responses.calls[1].request
        self.assertEqual(
            refresh_request.headers["Content-Type"], "application/x-www-form-urlencoded"
        )
        body = refresh_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        self.assertIn("grant_type=client_credentials", body)
        self.assertIn("client_id=test_client_id", body)
        self.assertIn("client_secret=test_client_secret", body)

    # Core Functionality Tests

    @responses.activate
    def test_find_remediation_incidents(self):
        creds = self.get_mock_credentials()

        responses.post(
            OAUTH_TOKEN_URLS["global"],
            json=self.get_mock_token_response(),
            status=200,
        )

        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json=self.get_mock_incidents_response(),
            status=200,
        )

        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)

        fetcher = MimecastFetcher(**creds)
        incidents = fetcher._find_remediation_incidents(start, end)

        self.assertEqual(len(incidents), 3)
        self.assertEqual(incidents[0]["code"], "TR-0001-00001-A")
        self.assertEqual(incidents[0]["type"], "automatic")

        find_request = responses.calls[1].request
        self.assertEqual(find_request.headers["Authorization"], "Bearer mock_access_token_12345")
        body = find_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body_json = json.loads(body)

        self.assertEqual(body_json["meta"]["pagination"]["pageSize"], 100)

        data = body_json["data"][0]
        format_str = "%Y-%m-%dT%H:%M:%S+0000"
        self.assertEqual(start.strftime(format_str), data["start"])
        self.assertEqual(end.strftime(format_str), data["end"])

        filter_by = data["filterBy"]
        self.assertEqual(filter_by["fieldName"], "type")
        self.assertEqual(filter_by["value"], "automatic,manual")

    @responses.activate
    def test_find_remediation_incidents_with_pagination(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        # First page with "next" token
        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json={
                "meta": {
                    "pagination": {
                        "pageSize": 2,
                        "next": "page2token",
                    }
                },
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-001",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg1@example.com>",
                                    "to": "user1@example.com",
                                },
                            },
                            {
                                "code": "TR-002",
                                "type": "manual",
                                "searchCriteria": {
                                    "messageId": "<msg2@example.com>",
                                    "to": "user2@example.com",
                                },
                            },
                        ]
                    }
                ],
            },
            status=200,
        )

        # Second page without "next" token (last page)
        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json={
                "meta": {
                    "pagination": {
                        "pageSize": 2,
                    }
                },
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-003",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg3@example.com>",
                                    "to": "user3@example.com",
                                },
                            },
                        ]
                    }
                ],
            },
            status=200,
        )

        fetcher = MimecastFetcher(**creds)

        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)

        incidents = fetcher._find_remediation_incidents(start, end)

        self.assertEqual(len(incidents), 3)
        self.assertEqual(incidents[0]["code"], "TR-001")
        self.assertEqual(incidents[1]["code"], "TR-002")
        self.assertEqual(incidents[2]["code"], "TR-003")

        # Call 0: OAuth, Call 1: first page, Call 2: second page
        second_page_request = responses.calls[2].request
        body = second_page_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body_json = json.loads(body)
        self.assertEqual(body_json["meta"]["pagination"]["pageToken"], "page2token")

        first_page_request = responses.calls[1].request
        body = first_page_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body_json = json.loads(body)
        self.assertNotIn("pageToken", body_json["meta"]["pagination"])

    @responses.activate
    def test_search_archive_for_message(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/message-finder/search",
            json=self.get_mock_archive_search_response("test_archive_id"),
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        start = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)

        archive_id = fetcher._search_archive_for_message("<msg@example.com>", start, end)

        self.assertEqual(archive_id, "test_archive_id")

        search_request = responses.calls[1].request
        self.assertEqual(search_request.headers["Authorization"], "Bearer mock_access_token_12345")
        body = search_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body_json = json.loads(body)

        data = body_json["data"][0]
        self.assertEqual(data["messageId"], "<msg@example.com>")
        self.assertEqual(data["searchReason"], ARCHIVE_SEARCH_REASON)
        format_str = "%Y-%m-%dT%H:%M:%S+0000"
        self.assertEqual(start.strftime(format_str), data["start"])
        self.assertEqual(end.strftime(format_str), data["end"])

    @responses.activate
    def test_search_archive_returns_none_when_not_found(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/message-finder/search",
            json={"data": [{"trackedEmails": []}]},
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        start = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)

        archive_id = fetcher._search_archive_for_message("<msg@example.com>", start, end)

        self.assertIsNone(archive_id)

    @responses.activate
    def test_search_archive_returns_none_on_http_error(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/message-finder/search",
            status=500,
        )

        fetcher = MimecastFetcher(**creds)
        start = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)

        archive_id = fetcher._search_archive_for_message("<msg@example.com>", start, end)

        self.assertIsNone(archive_id)

    @responses.activate
    def test_get_raw_message(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        raw_content = "From: sender@example.com\nTo: recipient@example.com\n\nTest body"
        presigned_url = "https://example.mimecast.com/download/message123"

        # API returns JSON with pre-signed URL
        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            json={"data": [{"url": presigned_url}]},
            status=200,
        )

        responses.get(
            presigned_url,
            body=raw_content,
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        result = fetcher._get_raw_message("archive_123", "user@example.com")

        self.assertEqual(result, raw_content)

        get_request = responses.calls[1].request
        self.assertEqual(get_request.headers["Authorization"], "Bearer mock_access_token_12345")
        body = get_request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        body_json = json.loads(body)

        data = body_json["data"][0]
        self.assertEqual(data["mailbox"], "user@example.com")
        self.assertEqual(data["id"], "archive_123")
        self.assertEqual(data["context"], "RECEIVED")
        self.assertEqual(data["type"], "RFC822")

        self.assertEqual(len(responses.calls), 3)  # OAuth + API + URL fetch
        self.assertEqual(responses.calls[2].request.url, presigned_url)

    @responses.activate
    def test_get_raw_message_returns_none_on_http_error(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            status=500,
        )

        fetcher = MimecastFetcher(**creds)
        result = fetcher._get_raw_message("archive_123", "user@example.com")

        self.assertIsNone(result)

    @responses.activate
    def test_get_raw_message_returns_none_on_json_error(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        # API returns error in the fail array
        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            json={"fail": [{"errors": [{"message": "Message not found"}]}], "data": []},
            status=200,
            headers={"Content-Type": "application/json"},
        )

        fetcher = MimecastFetcher(**creds)
        result = fetcher._get_raw_message("archive_123", "user@example.com")

        self.assertIsNone(result)

    @responses.activate
    def test_get_raw_message_returns_none_on_missing_url(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            json={"data": [{}]},
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        result = fetcher._get_raw_message("archive_123", "user@example.com")

        self.assertIsNone(result)

    @responses.activate
    def test_get_raw_message_returns_none_on_empty_data(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            json={"data": []},
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        result = fetcher._get_raw_message("archive_123", "user@example.com")

        self.assertIsNone(result)

    # Integration Tests

    @responses.activate
    def test_fetch_and_yield_emails(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        base_url = API_BASE_URLS["global"]
        presigned_url = "https://example.mimecast.com/download/msg1"

        responses.post(
            f"{base_url}/api/ttp/remediation/find-incidents",
            json={
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-001",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg1@example.com>",
                                    "to": "user1@example.com",
                                },
                            }
                        ]
                    }
                ]
            },
            status=200,
        )

        responses.post(
            f"{base_url}/api/message-finder/search",
            json=self.get_mock_archive_search_response("arch1"),
            status=200,
        )

        responses.post(
            f"{base_url}/api/archive/get-message-part",
            json={"data": [{"url": presigned_url}]},
            status=200,
        )

        responses.get(
            presigned_url,
            body="From: sender@example.com\n\nBody1",
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].user_id, "user1@example.com")
        self.assertIn("Body1", messages[0].raw)

    @responses.activate
    def test_skip_incident_without_message_id(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json={
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-001",
                                "type": "automatic",
                                "searchCriteria": {
                                    # Missing messageId
                                    "to": "user1@example.com",
                                },
                            }
                        ]
                    }
                ]
            },
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_skip_incident_without_recipient(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json={
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-001",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg1@example.com>",
                                    # Missing 'to'
                                },
                            }
                        ]
                    }
                ]
            },
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_multi_incident_processing_mixed_results(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        base_url = API_BASE_URLS["global"]
        presigned_url1 = "https://example.mimecast.com/download/msg1"
        presigned_url3 = "https://example.mimecast.com/download/msg3"

        # Mock find incidents - 3 incidents
        responses.post(
            f"{base_url}/api/ttp/remediation/find-incidents",
            json={
                "data": [
                    {
                        "incidents": [
                            {
                                "code": "TR-001",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg1@example.com>",
                                    "to": "user1@example.com",
                                },
                            },
                            {
                                "code": "TR-002",
                                "type": "manual",
                                "searchCriteria": {
                                    "messageId": "<msg2@example.com>",
                                    "to": "user2@example.com",
                                },
                            },
                            {
                                "code": "TR-003",
                                "type": "automatic",
                                "searchCriteria": {
                                    "messageId": "<msg3@example.com>",
                                    "to": "user3@example.com",
                                },
                            },
                        ]
                    }
                ]
            },
            status=200,
        )

        responses.post(
            f"{base_url}/api/message-finder/search",
            json=self.get_mock_archive_search_response("arch1"),
            status=200,
        )

        responses.post(
            f"{base_url}/api/message-finder/search",
            json={"data": [{"trackedEmails": []}]},
            status=200,
        )

        responses.post(
            f"{base_url}/api/message-finder/search",
            json=self.get_mock_archive_search_response("arch3"),
            status=200,
        )

        responses.post(
            f"{base_url}/api/archive/get-message-part",
            json={"data": [{"url": presigned_url1}]},
            status=200,
        )

        responses.get(
            presigned_url1,
            body="Email 1",
            status=200,
        )

        responses.post(
            f"{base_url}/api/archive/get-message-part",
            json={"data": [{"url": presigned_url3}]},
            status=200,
        )

        responses.get(
            presigned_url3,
            body="Email 3",
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].user_id, "user1@example.com")
        self.assertEqual(messages[1].user_id, "user3@example.com")

    @responses.activate
    def test_empty_incidents_list(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            json={"data": [{"incidents": []}]},
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_find_incidents_http_error_raises(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/ttp/remediation/find-incidents",
            status=500,
        )

        fetcher = MimecastFetcher(**creds)

        with self.assertRaises(requests.RequestException):
            list(fetcher.yield_remediated_emails())

    @responses.activate
    def test_archive_search_includes_correct_reason(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()

        responses.post(
            f"{API_BASE_URLS['global']}/api/message-finder/search",
            json=self.get_mock_archive_search_response(),
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        start = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)

        fetcher._search_archive_for_message("<msg@example.com>", start, end)

        # The OAuth token call is index 0, search call is index 1
        request_body = responses.calls[1].request.body
        self.assertIsNotNone(request_body)
        assert request_body is not None
        # request_body can be bytes or string depending on requests version
        if isinstance(request_body, bytes):
            self.assertIn(ARCHIVE_SEARCH_REASON.encode(), request_body)
        else:
            self.assertIn(ARCHIVE_SEARCH_REASON, request_body)

    @responses.activate
    def test_get_message_part_requests_rfc822_format(self):
        creds = self.get_mock_credentials()
        self.mock_oauth_token()
        presigned_url = "https://example.mimecast.com/download/test"

        responses.post(
            f"{API_BASE_URLS['global']}/api/archive/get-message-part",
            json={"data": [{"url": presigned_url}]},
            status=200,
        )

        responses.get(
            presigned_url,
            body="Test content",
            status=200,
        )

        fetcher = MimecastFetcher(**creds)
        fetcher._get_raw_message("archive_123", "user@example.com")

        # The OAuth token call is index 0, get-message-part call is index 1
        request_body = responses.calls[1].request.body
        self.assertIsNotNone(request_body)
        assert request_body is not None
        # request_body can be bytes or string depending on requests version
        if isinstance(request_body, bytes):
            self.assertIn(b'"type": "RFC822"', request_body)
            self.assertIn(b'"context": "RECEIVED"', request_body)
        else:
            self.assertIn('"type": "RFC822"', request_body)
            self.assertIn('"context": "RECEIVED"', request_body)


if __name__ == "__main__":
    unittest.main()
