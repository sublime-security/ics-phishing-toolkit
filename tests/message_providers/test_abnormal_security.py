import logging
import os
import unittest
from unittest.mock import patch

import responses

from common import Message
from message_providers.abnormal_security import (
    API_BASE_URL,
    MAX_RETRIES,
    AbnormalSecurityFetcher,
)


class TestAbnormalSecurityFetcher(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.api_key = "test_api_key_123"
        self.threat_id = "184712ab-6d8b-47b3-89d3-a314efef79e2"
        self.message_id_str = "4551618356913732000"

        # Patch time.sleep to make tests run instantly
        self.sleep_patcher = patch("message_providers.abnormal_security.time.sleep")
        self.mock_sleep = self.sleep_patcher.start()

    def tearDown(self):
        logging.disable(logging.NOTSET)
        self.sleep_patcher.stop()

    def test_init_with_valid_credentials(self):
        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)

        self.assertEqual(fetcher.api_key, self.api_key)
        self.assertEqual(fetcher.base_url, API_BASE_URL)
        self.assertEqual(fetcher.lookback_minutes, 5)
        self.assertEqual(fetcher.page_size, 100)
        self.assertEqual(fetcher.session.headers["Authorization"], f"Bearer {self.api_key}")

    def test_init_missing_credentials(self):
        with self.assertRaises(ValueError) as context:
            AbnormalSecurityFetcher(api_key="")

        self.assertIn("API key is required", str(context.exception))

    def test_init_with_custom_lookback_minutes(self):
        fetcher = AbnormalSecurityFetcher(api_key=self.api_key, lookback_minutes=720)
        self.assertEqual(fetcher.lookback_minutes, 720)

    @patch.dict(os.environ, {"MESSAGE_LOOKBACK_MINUTES": "2880"})
    def test_init_with_env_var_lookback_minutes(self):
        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        self.assertEqual(fetcher.lookback_minutes, 2880)

    @patch.dict(os.environ, {"MESSAGE_LOOKBACK_MINUTES": "invalid"})
    def test_init_with_invalid_env_var_lookback_minutes(self):
        with self.assertRaises(ValueError) as context:
            AbnormalSecurityFetcher(api_key=self.api_key)
        self.assertIn("must be a valid integer", str(context.exception))
        self.assertIn("invalid", str(context.exception))

    def test_init_with_negative_lookback_minutes(self):
        with self.assertRaises(ValueError) as context:
            AbnormalSecurityFetcher(api_key=self.api_key, lookback_minutes=-10)
        self.assertIn("must be a positive integer", str(context.exception))

    @patch.dict(os.environ, {"MESSAGE_LOOKBACK_MINUTES": "0"})
    def test_init_with_zero_env_var_lookback_minutes(self):
        with self.assertRaises(ValueError) as context:
            AbnormalSecurityFetcher(api_key=self.api_key)
        self.assertIn("must be a positive integer", str(context.exception))

    @responses.activate
    def test_fetch_remediated_threats_success(self):
        mock_response = {
            "threats": [
                {"threatId": "threat-1"},
                {"threatId": "threat-2"},
                {"threatId": "threat-3"},
            ],
            "pageNumber": 1,
            # No nextPageNumber means this is the last page
        }

        responses.get(
            f"{API_BASE_URL}/threats",
            json=mock_response,
            status=200,
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        threat_ids = fetcher._fetch_remediated_threats()

        self.assertEqual(len(threat_ids), 3)
        self.assertEqual(threat_ids, ["threat-1", "threat-2", "threat-3"])

        self.assertEqual(len(responses.calls), 1)
        request = responses.calls[0].request
        assert request.url is not None
        self.assertIn("filter=latestTimeRemediated", request.url)
        self.assertIn("pageSize=100", request.url)
        self.assertIn("pageNumber=1", request.url)

    @responses.activate
    def test_fetch_remediated_threats_pagination(self):
        page_1_response = {
            "threats": [{"threatId": "threat-1"}, {"threatId": "threat-2"}],
            "pageNumber": 1,
            "nextPageNumber": 2,
        }

        page_2_response = {
            "threats": [{"threatId": "threat-3"}, {"threatId": "threat-4"}],
            "pageNumber": 2,
            "nextPageNumber": 3,
        }

        page_3_response = {
            "threats": [{"threatId": "threat-5"}],
            "pageNumber": 3,
        }

        responses.get(f"{API_BASE_URL}/threats", json=page_1_response, status=200)
        responses.get(f"{API_BASE_URL}/threats", json=page_2_response, status=200)
        responses.get(f"{API_BASE_URL}/threats", json=page_3_response, status=200)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        threat_ids = fetcher._fetch_remediated_threats()

        self.assertEqual(len(threat_ids), 5)
        self.assertEqual(threat_ids, ["threat-1", "threat-2", "threat-3", "threat-4", "threat-5"])
        self.assertEqual(len(responses.calls), 3)

    @responses.activate
    def test_get_threat_messages_success(self):
        mock_response = {
            "threatId": self.threat_id,
            "messages": [
                {
                    "abxMessageIdStr": "123456",
                    "recipientAddress": "user1@example.com",
                },
                {
                    "abxMessageIdStr": "789012",
                    "recipientAddress": "user2@example.com",
                },
            ],
        }

        responses.get(
            f"{API_BASE_URL}/threats/{self.threat_id}",
            json=mock_response,
            status=200,
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = fetcher._get_threat_messages(self.threat_id)

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0], ("123456", "user1@example.com"))
        self.assertEqual(messages[1], ("789012", "user2@example.com"))

    @responses.activate
    def test_download_message_success(self):
        eml_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
MIME-Version: 1.0
Content-Type: text/calendar; charset="utf-8"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:test-uid-123
SUMMARY:Test Meeting
END:VEVENT
END:VCALENDAR"""

        responses.get(
            f"{API_BASE_URL}/messages/4551618356913732000/download",
            body=eml_content,
            status=200,
            content_type="message/rfc822",
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        content = fetcher._download_message(self.message_id_str)

        self.assertIsNotNone(content)
        content = content or ""
        self.assertIn("BEGIN:VCALENDAR", content)
        self.assertIn("test-uid-123", content)

    @responses.activate
    def test_download_message_404(self):
        responses.get(
            f"{API_BASE_URL}/messages/4551618356913732000/download",
            status=404,
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        content = fetcher._download_message(self.message_id_str)

        self.assertIsNone(content)

    def test_download_message_invalid_message_id(self):
        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        content = fetcher._download_message("invalid_id")

        self.assertIsNone(content)

    @responses.activate
    def test_yield_remediated_emails_integration(self):
        threats_response = {
            "threats": [{"threatId": self.threat_id}],
            "pageNumber": 1,
        }

        details_response = {
            "threatId": self.threat_id,
            "messages": [
                {
                    "abxMessageIdStr": "123456",
                    "recipientAddress": "user@example.com",
                }
            ],
        }

        eml_content = """From: sender@example.com
To: user@example.com
Subject: Test Meeting Invitation
MIME-Version: 1.0
Content-Type: text/calendar; charset="utf-8"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:test-meeting-uid
SUMMARY:Test Meeting
END:VEVENT
END:VCALENDAR"""

        responses.get(f"{API_BASE_URL}/threats", json=threats_response, status=200)
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", json=details_response, status=200)
        responses.get(
            f"{API_BASE_URL}/messages/123456/download",
            body=eml_content,
            status=200,
            content_type="message/rfc822",
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 1)
        self.assertIsInstance(messages[0], Message)
        self.assertEqual(messages[0].user_id, "user@example.com")
        self.assertIn("BEGIN:VCALENDAR", messages[0].raw)
        self.assertIn("Test Meeting", messages[0].raw)

    @responses.activate
    def test_error_handling_failed_threats_fetch(self):
        responses.get(f"{API_BASE_URL}/threats", status=500)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        threat_ids = fetcher._fetch_remediated_threats()

        self.assertEqual(len(threat_ids), 0)

    @responses.activate
    def test_error_handling_failed_messages_fetch(self):
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", status=500)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = fetcher._get_threat_messages(self.threat_id)

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_empty_results_no_threats(self):
        empty_response = {"threats": [], "pageNumber": 1}

        responses.get(f"{API_BASE_URL}/threats", json=empty_response, status=200)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_empty_results_no_messages(self):
        threats_response = {"threats": [{"threatId": self.threat_id}], "pageNumber": 1}
        details_response = {
            "threatId": self.threat_id,
            "messages": [],
        }

        responses.get(f"{API_BASE_URL}/threats", json=threats_response, status=200)
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", json=details_response, status=200)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 0)

    @responses.activate
    def test_multiple_messages_per_threat(self):
        threats_response = {"threats": [{"threatId": self.threat_id}], "pageNumber": 1}

        details_response = {
            "threatId": self.threat_id,
            "messages": [
                {"abxMessageIdStr": "111", "recipientAddress": "user1@example.com"},
                {"abxMessageIdStr": "222", "recipientAddress": "user2@example.com"},
            ],
        }

        eml_content = """From: sender@example.com
To: recipient@example.com
Subject: Meeting Invitation
MIME-Version: 1.0
Content-Type: text/calendar; charset="utf-8"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:meeting-uid
SUMMARY:Meeting
END:VEVENT
END:VCALENDAR"""

        responses.get(f"{API_BASE_URL}/threats", json=threats_response, status=200)
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", json=details_response, status=200)
        responses.get(
            f"{API_BASE_URL}/messages/111/download",
            body=eml_content,
            status=200,
            content_type="message/rfc822",
        )
        responses.get(
            f"{API_BASE_URL}/messages/222/download",
            body=eml_content,
            status=200,
            content_type="message/rfc822",
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 2)
        self.assertIsInstance(messages[0], Message)
        self.assertIsInstance(messages[1], Message)
        recipients = {msg.user_id for msg in messages}
        self.assertEqual(recipients, {"user1@example.com", "user2@example.com"})
        for msg in messages:
            self.assertIn("BEGIN:VCALENDAR", msg.raw)

    @responses.activate
    def test_failed_message_download(self):
        threats_response = {"threats": [{"threatId": self.threat_id}], "pageNumber": 1}

        details_response = {
            "threatId": self.threat_id,
            "messages": [
                {"abxMessageIdStr": "111", "recipientAddress": "user1@example.com"},
                {"abxMessageIdStr": "222", "recipientAddress": "user2@example.com"},
            ],
        }

        eml_content = """From: sender@example.com
To: user2@example.com
Subject: Meeting
MIME-Version: 1.0
Content-Type: text/calendar; charset="utf-8"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:uid-222
END:VEVENT
END:VCALENDAR"""

        responses.get(f"{API_BASE_URL}/threats", json=threats_response, status=200)
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", json=details_response, status=200)
        responses.get(f"{API_BASE_URL}/messages/111/download", status=404)
        responses.get(
            f"{API_BASE_URL}/messages/222/download",
            body=eml_content,
            status=200,
            content_type="message/rfc822",
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].user_id, "user2@example.com")

    @responses.activate
    def test_rate_limiting_with_retry(self):
        responses.get(f"{API_BASE_URL}/threats", status=429)
        responses.get(
            f"{API_BASE_URL}/threats",
            json={"threats": [{"threatId": self.threat_id}], "pageNumber": 1},
            status=200,
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        threat_ids = fetcher._fetch_remediated_threats()

        self.assertEqual(len(threat_ids), 1)
        self.assertEqual(threat_ids[0], self.threat_id)
        self.assertEqual(len(responses.calls), 2)

    @responses.activate
    def test_rate_limiting_exhausted_retries(self):
        for _ in range(MAX_RETRIES):
            responses.get(f"{API_BASE_URL}/threats", status=429)

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        threat_ids = fetcher._fetch_remediated_threats()

        self.assertEqual(len(threat_ids), 0)
        self.assertEqual(len(responses.calls), MAX_RETRIES)

    @responses.activate
    def test_server_error_with_retry(self):
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", status=500)
        responses.get(
            f"{API_BASE_URL}/threats/{self.threat_id}",
            json={
                "threatId": self.threat_id,
                "messages": [{"abxMessageIdStr": "123", "recipientAddress": "user@example.com"}],
            },
            status=200,
        )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = fetcher._get_threat_messages(self.threat_id)

        self.assertEqual(len(messages), 1)
        self.assertEqual(len(responses.calls), 2)

    @responses.activate
    def test_many_messages_per_threat(self):
        threats_response = {"threats": [{"threatId": self.threat_id}], "pageNumber": 1}

        details_response = {
            "threatId": self.threat_id,
            "messages": [
                {"abxMessageIdStr": str(i), "recipientAddress": f"user{i}@example.com"}
                for i in range(50)
            ],
        }

        eml_content = """From: sender@example.com
To: recipient@example.com
Subject: Meeting
MIME-Version: 1.0
Content-Type: text/calendar; charset="utf-8"

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:event-uid
SUMMARY:Event
END:VEVENT
END:VCALENDAR"""

        responses.get(f"{API_BASE_URL}/threats", json=threats_response, status=200)
        responses.get(f"{API_BASE_URL}/threats/{self.threat_id}", json=details_response, status=200)

        for i in range(50):
            responses.get(
                f"{API_BASE_URL}/messages/{i}/download",
                body=eml_content,
                status=200,
                content_type="message/rfc822",
            )

        fetcher = AbnormalSecurityFetcher(api_key=self.api_key)
        messages = list(fetcher.yield_remediated_emails())

        self.assertEqual(len(messages), 50)

        for msg in messages:
            self.assertIsInstance(msg, Message)
            self.assertIn("BEGIN:VCALENDAR", msg.raw)


if __name__ == "__main__":
    unittest.main()
