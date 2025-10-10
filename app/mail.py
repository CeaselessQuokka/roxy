import auth
import smtplib
from email.message import EmailMessage

APP_PASSWORD = auth.read_app_password()
FROM = "pluginsroblox@gmail.com"


def send(to: str, subject: str, body: str):
    email = EmailMessage()
    email["To"] = to
    email["From"] = FROM
    email["Subject"] = subject
    email.set_content(body)

    # Gmail SMTP server
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(FROM, APP_PASSWORD)
        smtp.send_message(email)
