# ics-phishing-toolkit

This toolkit for remediating malicious calendar invites is designed to help teams using email security solutions that
don't natively remediate these attacks.

If you're using Sublime, you don't need this toolkit
because [remediation is natively supported](https://sublime.security/attack-types/ics-phishing/).

## Supported stacks

Stack-specific standalone scripts (e.g., `proofpoint-microsoft365.py`, `mimecast-google-workspace.py`) are
provided for each combination of these email security providers and calendar providers:

**Email security providers:**
- Proofpoint
- Mimecast
- Abnormal Security

**Calendar providers:**
- Microsoft 365
- Google Workspace

Go to [Quickstart](#quickstart) to get right to it!

Not seeing your stack? Don't hesitate to tell us what stack you want supported at <opensource@sublimesecurity.com>.

## Detection

These scripts require an email security solution that is already detecting ICS phishing emails, but that is not
removing the calendar events created through those emails.

If you don't have an email security solution detecting ICS phishing, [Sublime Core](https://sublime.security/start/)
offers free and self-hostable email security with built-in ICS phishing detection and automatic calendar remediation.

## The rise of ICS phishing

**ICS phishing** is a two-pronged attack that delivers malicious payloads to both a user's inbox and calendar
simultaneously. This attack vector saw a ~100x increase from Q1 to Q4 2025, per
Sublime's [2026 Email Threat Research Report](https://sublime.security/resources/email-threat-research-report-2026/),
with over 20% of Q4 callback phishing attacks using calendar invites as a delivery mechanism.

The critical security gap: **calendar events persist even when email security solutions quarantine or delete the
malicious email**. This affects both secure email gateways (SEGs) and API-based email security solutions, most of which
do not clean up malicious calendar events as of February 2026.

## Stopping ICS phishing

Based on [Sublime's built-in remediation](https://sublime.security/attack-types/ics-phishing/) of malicious calendar
events, these Python scripts automatically delete malicious events when your email security solution quarantines ICS
phishing emails. The scripts:

- Fetch quarantined messages from your email security provider
- Extract `.ics` calendar attachments and other [iCalendar](https://en.wikipedia.org/wiki/ICalendar)-compliant
  attachments from those messages
- Find and delete matching events from users' calendars (Microsoft 365 or Google Workspace)

### SOARs

As pure Python, you can run these scripts in many SOARs, including Tines, Splunk SOAR, and Cortex XSOAR.

We're also working on SOAR-specific guides. Please reach out to <opensource@sublimesecurity.com> if you need help
or want to be notified when we publish documentation for a particular SOAR.

## Quickstart

Each standalone script requires:

1. A compatible [runtime](#runtimes)
2. Environment variables containing API credentials
3. Appropriate API permissions for your email security solution and calendar provider

### Runtimes

You can run these scripts in any environment with:

- Python 3.9 or later
- Support for installing the PyPI packages listed in `requirements.txt` (`requests` and `PyJWT`)

For production deployments, you'll also want to schedule the script to run regularly, e.g., with a cron job.

### Configuration

The scripts run in dry-run mode by default to prevent accidental deletion of events.
See [configuration options](#configuration-options) for how to enable deletion and how to implement custom logic in
response to discovery of malicious invitations and events.

### Proofpoint Cloud

```bash
export PROOFPOINT_CLIENT_ID="your-client-id"
export PROOFPOINT_CLIENT_SECRET="your-client-secret"
```

- `PROOFPOINT_CLIENT_ID`: OAuth 2.0 client ID for Proofpoint Cloud Threat Response API
- `PROOFPOINT_CLIENT_SECRET`: OAuth 2.0 client secret

### Mimecast

```bash
export MIMECAST_CLIENT_ID="your-client-id"
export MIMECAST_CLIENT_SECRET="your-client-secret"
export MIMECAST_REGION="global"  # Options: global, us, uk (default: global)
```

- `MIMECAST_CLIENT_ID`: OAuth 2.0 client ID for Mimecast API 2.0
- `MIMECAST_CLIENT_SECRET`: OAuth 2.0 client secret
- `MIMECAST_REGION`: API region endpoint (optional, defaults to global)

**Required API Permissions:**
- `Services | Threat Remediation | Read`
- `Gateway | Tracking | Read`
- `Archive | Read`

### Abnormal Security

```bash
export ABNORMAL_API_KEY="your-api-key"
```

- `ABNORMAL_API_KEY`: API key from Abnormal Security platform

### Google Workspace

```bash
# Option 1: Service Account File
export GOOGLE_SERVICE_ACCOUNT_FILE="/path/to/service-account.json"

# Option 2: Service Account JSON (inline)
export GOOGLE_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'
```

- `GOOGLE_SERVICE_ACCOUNT_FILE`: Path to service account JSON key file
- `GOOGLE_SERVICE_ACCOUNT_JSON`: Inline service account credentials as JSON string

**Required Setup:**
- Enable domain-wide delegation for the service account
- Authorize scope: `https://www.googleapis.com/auth/calendar.events`
- Configure in [Google Workspace Admin Console](https://support.google.com/a/answer/162106)

### Microsoft 365

```bash
export MICROSOFT_CLIENT_ID="your-client-id"
export MICROSOFT_CLIENT_SECRET="your-client-secret"
export MICROSOFT_TENANT_ID="your-tenant-id"
```

- `MICROSOFT_CLIENT_ID`: Azure AD application (client) ID
- `MICROSOFT_CLIENT_SECRET`: Azure AD application client secret
- `MICROSOFT_TENANT_ID`: Azure AD directory (tenant) ID

**Required API Permission:** `Calendars.ReadWrite` (Application permission)

### Example: Proofpoint + Microsoft 365

```bash
export ICS_PHISHING_REMEDIATION_MODE="dry_run" # "dry_run" is default
export MESSAGE_LOOKBACK_MINUTES=10

export PROOFPOINT_CLIENT_ID="your-client-id"
export PROOFPOINT_CLIENT_SECRET="your-secret"
export MICROSOFT_TENANT_ID="your-tenant"
export MICROSOFT_CLIENT_ID="your-client"
export MICROSOFT_CLIENT_SECRET="your-secret"

python3 proofpoint-microsoft365.py
```

## Configuration options

### Dry run mode (default)

**By default, all scripts run in dry-run mode** to prevent accidental deletions. In this mode, the script will:
- Fetch quarantined emails and extract calendar invitations
- Search for matching calendar events
- **Log what events would be deleted without actually deleting anything**

This allows you to verify the script is working correctly before enabling actual deletion.

#### Enabling deletion

To actually delete calendar events, set the `ICS_PHISHING_REMEDIATION_MODE` environment variable:

```bash
export ICS_PHISHING_REMEDIATION_MODE="delete_events"
```

Valid values:
- `dry_run` (default) - Preview actions without deleting
- `delete_events` - Actually delete matching calendar events

Invalid values will raise an error to prevent misconfiguration.

### Message lookback window

All scripts search for quarantined messages within a configurable time window:

```bash
export MESSAGE_LOOKBACK_MINUTES=10  # Optional, defaults to 5 minutes
```

**Important:** This value should match your cron schedule frequency with a small buffer to ensure no messages
are missed. For example, if running every 5 minutes, set the lookback window to 10 minutes.

### Custom callbacks

For additional integrations, such as with logging systems or monitoring tools, you can implement custom callbacks in
your script and pass them to the `delete_events_from_remediated_emails` function:

- `on_invitation_found_callback(invitation: CalendarInvitation)` - Called when a calendar invitation is found in a
  quarantined message
- `on_event_found_callback(invitation: CalendarInvitation, event: CalendarEvent)` - Called for each matching calendar event

Example:

```python
def log_invitation(invitation):
    print(f"Found malicious invitation for {invitation.user_id}, UID: {invitation.ics_uid}")

def log_event(invitation, event):
    print(f"Found calendar event {event.id} matching invitation {invitation.ics_uid}")

fetcher = ProofpointCloudFetcher()
deleter = GoogleWorkspaceEventDeleter()

delete_events_from_remediated_emails(
    fetcher,
    deleter,
    mode="delete_events",  # Override default dry_run mode
    on_invitation_found_callback=log_invitation,
    on_event_found_callback=log_event
)
```

Note: Errors in callbacks are logged but do not stop event processing.

## Architecture

All scripts follow a common pattern defined in `common.py`:

```python
class MessageFetcher:
    def yield_remediated_emails(self) -> Iterator[Message]:
        """Fetch quarantined messages from your email security solution"""

class EventDeleter:
    def delete_matching_events(
        self,
        invitation: CalendarInvitation,
        mode: Mode,
        on_event_found_callback: Optional[Callable[[CalendarInvitation, CalendarEvent], None]]
    ) -> None:
        """Delete calendar events matching the ICS attachment"""
```

Stack-specific implementations handle API authentication and provider-specific logic.

## Getting help

- **Questions, feature requests, or bug reports:** <opensource@sublimesecurity.com>
- **SOAR integration guides:** Contact us at <opensource@sublimesecurity.com> for early access to detailed deployment
  guides for your SOAR platform
- **Threat intelligence:** Read our [ICS phishing blog post](https://sublime.security/blog/ics-phishing-stopping-a-surge-of-malicious-calendar-invites) and
  [2026 Email Threat Research Report](https://sublime.security/resources/email-threat-research-report-2026/)
