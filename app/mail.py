import auth
import logging
import smtplib
from email.message import EmailMessage

APP_PASSWORD = auth.read_app_password()
FROM = auth.get_emails()[1]
SMTP_TIMEOUT = 15  # In seconds; a hung SMTP connection must never hang a worker indefinitely.

_logger = logging.getLogger("roxy.mail")


def send(to: str, subject: str, body: str):
    """Send an email. Raises on failure — use try_send() when failure must not propagate."""
    email = EmailMessage()
    email["To"] = to
    email["From"] = FROM
    email["Subject"] = subject
    email.set_content(body)

    # Gmail SMTP server
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=SMTP_TIMEOUT) as smtp:
        smtp.login(FROM, APP_PASSWORD)
        smtp.send_message(email)


def try_send(to: str, subject: str, body: str) -> bool:
    """Send an email, swallowing any failure. Returns True if it was sent."""
    try:
        send(to, subject, body)
        return True
    except Exception:
        _logger.exception("Failed to send email %r to %s", subject, to)
        return False
