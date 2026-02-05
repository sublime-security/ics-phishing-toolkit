from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def generate_eml_with_invite(email_address: str, ics_uid: str) -> str:
    msg = MIMEMultipart("mixed")
    msg["From"] = "sender@example.com"
    msg["To"] = email_address
    msg["Subject"] = "Calendar Invitation"
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")
    msg["Message-ID"] = f"<{datetime.now(timezone.utc).timestamp()}@example.com>"

    text_body = MIMEText("Please see the attached calendar invitation.", "plain")
    msg.attach(text_body)

    ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Mock Security Tool//EN
METHOD:REQUEST
BEGIN:VEVENT
UID:{ics_uid}
DTSTAMP:{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}
DTSTART:{(datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y%m%dT%H%M%SZ")}
DTEND:{(datetime.now(timezone.utc) + timedelta(days=1, hours=1)).strftime("%Y%m%dT%H%M%SZ")}
SUMMARY:Test Meeting
ORGANIZER:mailto:sender@example.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:{email_address}
STATUS:CONFIRMED
SEQUENCE:0
END:VEVENT
END:VCALENDAR
"""

    ics_part = MIMEBase("text", "calendar", method="REQUEST", name="invite.ics")
    ics_part.set_payload(ics_content.encode("utf-8"))
    encoders.encode_base64(ics_part)
    ics_part.add_header("Content-Disposition", "attachment", filename="invite.ics")
    ics_part.add_header("Content-Transfer-Encoding", "base64")
    msg.attach(ics_part)

    return msg.as_string()
