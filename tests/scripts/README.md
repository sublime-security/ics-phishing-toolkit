# Testing Scripts

This directory contains scripts for testing calendar event deletion with mock message providers

## run_with_mock_message_provider.py

Test script that loads EML files and processes them using either Google Workspace or Microsoft 365 EventDeleters.

### Prerequisites

- Python 3.9+
- Required dependencies installed (see `src/requirements.txt`)
- Valid credentials file in `.credentials/` directory

### Credentials Setup

Place your credentials in the `.credentials/` directory:

**Google Workspace** (`.credentials/google.json`):
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "...",
  "private_key": "...",
  "client_email": "...",
  "client_id": "...",
  ...
}
```

**Microsoft 365** (`.credentials/microsoft.json`):
```json
{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "tenant_id": "your-tenant-id"
}
```

### Usage

```bash
python tests/scripts/run_with_mock_message_provider.py <cal_provider> <eml_file> [<eml_file> ...]
```

**Arguments:**
- `cal_provider`: Calendar provider to use (`google` or `microsoft`)
- `eml_file`: One or more absolute paths to EML files

### Examples

**Test with Google Workspace:**
```bash
python tests/scripts/run_with_mock_message_provider.py google \
  /Users/you/repos/ics-phishing/tests/scripts/test_emls/my_test.eml
```

**Test with Microsoft 365:**
```bash
python tests/scripts/run_with_mock_message_provider.py microsoft \
  /Users/you/repos/ics-phishing/tests/scripts/test_emls/my_test.eml
```

### What It Does

1. Loads EML files from the specified paths
2. Extracts recipient email addresses from the EML headers
3. Instantiates a mock `MessageFetcher` that yields `Message` objects for the provide EMLs
4. Runs `common.delete_events_from_remediated_emails` with the MessageFetcher and the selected `EventDeleter`
