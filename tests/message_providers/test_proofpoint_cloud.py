import logging
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import responses
from requests import HTTPError

from message_providers.proofpoint_cloud import API_BASE_URL, TOKEN_BASE_URL, ProofpointCloudFetcher


class TestProofpointCloudFetcher(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

        for var in ["PROOFPOINT_CLIENT_ID", "PROOFPOINT_CLIENT_SECRET", "MESSAGE_LOOKBACK_MINUTES"]:
            os.environ.pop(var, None)

    def tearDown(self):
        logging.disable(logging.NOTSET)

        for var in ["PROOFPOINT_CLIENT_ID", "PROOFPOINT_CLIENT_SECRET", "MESSAGE_LOOKBACK_MINUTES"]:
            os.environ.pop(var, None)

    def get_mock_token_response(self):
        return {"access_token": "test_token_123", "expires_in": 3600}

    def get_mock_messages_response(self):
        return {
            "messages": [
                {"id": "msg1", "recipient_address": "user1@example.com"},
                {"id": "msg2", "recipient_address": "user2@example.com"},
                {"id": "msg3"},  # Missing recipient
            ]
        }

    @responses.activate
    def test_token_refresh_on_init(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")

        self.assertEqual(fetcher._access_token, "test_token_123")
        self.assertEqual(fetcher.session.headers["Authorization"], "Bearer test_token_123")

    @responses.activate
    def test_credentials_from_environment_variables(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)

        os.environ["PROOFPOINT_CLIENT_ID"] = "test_client_id"
        os.environ["PROOFPOINT_CLIENT_SECRET"] = "test_client_secret"

        fetcher = ProofpointCloudFetcher()

        self.assertEqual(fetcher.client_id, "test_client_id")
        self.assertEqual(fetcher.client_secret, "test_client_secret")
        self.assertEqual(fetcher._access_token, "test_token_123")
        self.assertEqual(fetcher.session.headers["Authorization"], "Bearer test_token_123")

    @patch("time.sleep")
    @responses.activate
    def test_fetch_and_yield_emails(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json=self.get_mock_messages_response(),
            status=200,
        )

        # Mock fetch and status for msg1
        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetched"},
            status=200,
        )
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/download",
            body="From: sender@example.com\nSubject: Test\n\nBody",
            status=200,
        )

        # Mock fetch and status for msg2
        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg2/fetch", status=200)
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg2/fetchStatus",
            json={"messageStatus": "fetched"},
            status=200,
        )
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg2/download",
            body="From: sender2@example.com\nSubject: Test2\n\nBody2",
            status=200,
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].user_id, "user1@example.com")
        self.assertIn("Test", messages[0].raw)
        self.assertEqual(messages[1].user_id, "user2@example.com")
        self.assertIn("Test2", messages[1].raw)

    @responses.activate
    def test_skip_message_without_recipient(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages", json={"messages": [{"id": "msg1"}]}, status=200
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @patch("time.sleep")
    @responses.activate
    def test_download_with_polling_states(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)

        # First call returns in_progress, second returns fetched
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetch_in_progress"},
            status=200,
        )
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetched"},
            status=200,
        )

        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/download", body="Email content", status=200
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].raw, "Email content")

        mock_sleep.assert_called_once_with(5)

    @responses.activate
    def test_download_returns_none_on_error_status(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "error"},
            status=200,
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_token_auto_refresh_when_expired(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")

        # Manually expire the token
        fetcher._token_expires_at = datetime.now(timezone.utc)

        responses.post(
            TOKEN_BASE_URL, json={"access_token": "new_token", "expires_in": 3600}, status=200
        )
        responses.post(f"{API_BASE_URL}/api/v1/tric/messages", json={"messages": []}, status=200)

        list(fetcher.yield_remediated_emails())

        self.assertEqual(fetcher._access_token, "new_token")

    @patch("time.sleep")
    @responses.activate
    def test_pagination_fetches_all_messages(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)

        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={
                "messages": [
                    {"id": f"msg{i}", "recipient_address": f"user{i}@example.com"} for i in range(5)
                ]
            },
            status=200,
        )

        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={
                "messages": [
                    {"id": f"msg{i}", "recipient_address": f"user{i}@example.com"}
                    for i in range(5, 8)
                ]
            },
            status=200,
        )

        for i in range(8):
            responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg{i}/fetch", status=200)
            responses.get(
                f"{API_BASE_URL}/api/v1/tric/messages/msg{i}/fetchStatus",
                json={"messageStatus": "fetched"},
                status=200,
            )
            responses.get(
                f"{API_BASE_URL}/api/v1/tric/messages/msg{i}/download",
                body=f"Email {i}",
                status=200,
            )

        fetcher = ProofpointCloudFetcher(
            client_id="test_id", client_secret="test_secret", batch_size=5
        )
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 8)
        self.assertEqual(messages[0].user_id, "user0@example.com")
        self.assertEqual(messages[7].user_id, "user7@example.com")

    def test_missing_credentials_raises_error(self):
        with self.assertRaises(ValueError) as context:
            ProofpointCloudFetcher(client_id="", client_secret="")
        self.assertIn("credentials are required", str(context.exception))

    @responses.activate
    def test_init_with_default_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        self.assertEqual(fetcher.lookback_minutes, 5)

    @responses.activate
    def test_init_with_custom_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        fetcher = ProofpointCloudFetcher(
            client_id="test_id", client_secret="test_secret", lookback_minutes=720
        )
        self.assertEqual(fetcher.lookback_minutes, 720)

    @responses.activate
    def test_init_with_env_var_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "2880"
        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        self.assertEqual(fetcher.lookback_minutes, 2880)

    @responses.activate
    def test_init_with_invalid_env_var_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "invalid"
        with self.assertRaises(ValueError) as context:
            ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        self.assertIn("must be a valid integer", str(context.exception))
        self.assertIn("invalid", str(context.exception))

    @responses.activate
    def test_init_with_negative_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        with self.assertRaises(ValueError) as context:
            ProofpointCloudFetcher(
                client_id="test_id", client_secret="test_secret", lookback_minutes=-10
            )
        self.assertIn("must be a positive integer", str(context.exception))

    @responses.activate
    def test_init_with_zero_env_var_lookback_minutes(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        os.environ["MESSAGE_LOOKBACK_MINUTES"] = "0"
        with self.assertRaises(ValueError) as context:
            ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        self.assertIn("must be a positive integer", str(context.exception))

    @patch("message_providers.proofpoint_cloud.POLLING_TIMEOUT_SECONDS", 0.1)
    @patch("message_providers.proofpoint_cloud.FETCH_IN_PROGRESS_SLEEP_SECONDS", 0.01)
    @responses.activate
    def test_download_timeout_returns_none(
        self,
    ):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)

        # Always return fetch_in_progress to force timeout
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetch_in_progress"},
            status=200,
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @patch("time.sleep")
    @responses.activate
    def test_throttled_status_waits_30_seconds(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)

        # First call returns throttled, second returns fetched
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "throttled"},
            status=200,
        )
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetched"},
            status=200,
        )

        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/download", body="Email content", status=200
        )

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 1)
        mock_sleep.assert_called_once_with(30)

    @responses.activate
    def test_fetch_initiation_failure_returns_none(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=500)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @patch("time.sleep")
    @responses.activate
    def test_status_check_failure_returns_none(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus", status=500)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @patch("time.sleep")
    @responses.activate
    def test_download_failure_returns_none(self, mock_sleep):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(
            f"{API_BASE_URL}/api/v1/tric/messages",
            json={"messages": [{"id": "msg1", "recipient_address": "user@example.com"}]},
            status=200,
        )

        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetch", status=200)
        responses.get(
            f"{API_BASE_URL}/api/v1/tric/messages/msg1/fetchStatus",
            json={"messageStatus": "fetched"},
            status=200,
        )

        # Download fails with 500
        responses.get(f"{API_BASE_URL}/api/v1/tric/messages/msg1/download", status=500)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_token_refresh_failure_raises_exception(self):
        responses.post(TOKEN_BASE_URL, status=401)

        with self.assertRaises(HTTPError):
            ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")

    @responses.activate
    def test_fetch_messages_http_error(self):
        responses.post(TOKEN_BASE_URL, json=self.get_mock_token_response(), status=200)
        responses.post(f"{API_BASE_URL}/api/v1/tric/messages", status=500)

        fetcher = ProofpointCloudFetcher(client_id="test_id", client_secret="test_secret")

        with self.assertRaises(HTTPError):
            list(fetcher.yield_remediated_emails())


if __name__ == "__main__":
    unittest.main()
