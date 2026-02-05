import argparse
import json
import logging
import sys
from collections.abc import Iterator
from email import message_from_string
from pathlib import Path

src_dir = Path(__file__).resolve().parent.parent.parent / "src/"
sys.path.insert(0, str(src_dir))

from calendar_providers.google_workspace import GoogleWorkspaceEventDeleter  # noqa: E402
from calendar_providers.microsoft365 import Microsoft365EventDeleter  # noqa: E402
from common import (  # noqa: E402
    EventDeleter,
    Message,
    MessageFetcher,
    delete_events_from_remediated_emails,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockMessageFetcher(MessageFetcher):
    def __init__(self, messages: list[Message]):
        self.messages = messages

    def yield_remediated_emails(self) -> Iterator[Message]:
        yield from self.messages


def load_eml_files(file_paths: list[str]) -> list[Message]:
    """Load EML files from the given paths and convert them to Message objects."""
    messages = []

    for file_path in file_paths:
        path = Path(file_path)

        if not path.exists():
            logger.error(f"File not found: {file_path}")
            continue

        if not path.is_file():
            logger.error(f"Not a file: {file_path}")
            continue

        try:
            raw_content: str
            with open(path, encoding="utf-8") as f:
                raw_content = f.read()

            # Parse the email to extract the recipient's email address
            email_msg = message_from_string(raw_content)

            # Extract user_id from the 'To' header, fallback to 'Delivered-To' or 'X-Original-To'
            user_id = (
                email_msg.get("To")
                or email_msg.get("Delivered-To")
                or email_msg.get("X-Original-To")
                or "unknown@example.com"
            )

            # If user_id contains name and email like "Name <email@domain.com>",
            # extract just the email
            if "<" in user_id and ">" in user_id:
                user_id = user_id[user_id.index("<") + 1 : user_id.index(">")]

            message = Message(user_id=user_id.strip(), raw=raw_content)
            messages.append(message)
            logger.info(f"Loaded EML file: {file_path} (user_id: {message.user_id})")

        except Exception as e:
            logger.error(f"Failed to load EML file {file_path}: {e}")
            continue

    return messages


def create_event_deleter(cal_provider: str) -> EventDeleter:
    """Create the appropriate EventDeleter based on the calendar provider."""
    credentials_dir = Path(__file__).parent / ".credentials"

    if cal_provider == "google":
        credentials_path = credentials_dir / "google.json"
        if not credentials_path.exists():
            logger.error(f"Google credentials file not found at: {credentials_path}")
            sys.exit(1)

        logger.info("Using Google Workspace EventDeleter")
        return GoogleWorkspaceEventDeleter(service_account_file=str(credentials_path))

    elif cal_provider == "microsoft":
        credentials_path = credentials_dir / "microsoft.json"
        if not credentials_path.exists():
            logger.error(f"Microsoft credentials file not found at: {credentials_path}")
            sys.exit(1)

        creds: dict
        with open(credentials_path) as f:
            creds = json.load(f)

        logger.info("Using Microsoft 365 EventDeleter")
        return Microsoft365EventDeleter(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            tenant_id=creds["tenant_id"],
        )

    else:
        logger.error(f"Unsupported calendar provider: {cal_provider}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Run event deletion with mock message provider using EML files."
    )
    parser.add_argument(
        "cal_provider",
        choices=["google", "microsoft"],
        help="Calendar provider to use (google or microsoft)",
    )
    parser.add_argument("eml_files", nargs="+", help="One or more absolute paths to EML files")

    args = parser.parse_args()

    messages = load_eml_files(args.eml_files)

    if not messages:
        logger.error("No messages were successfully loaded. Exiting.")
        sys.exit(1)

    logger.info(f"Loaded {len(messages)} message(s)")

    fetcher = MockMessageFetcher(messages)
    deleter = create_event_deleter(args.cal_provider)

    delete_events_from_remediated_emails(fetcher, deleter)

    logger.info("Processing complete")


if __name__ == "__main__":
    main()
