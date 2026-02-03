import smtplib
from email.message import EmailMessage

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 2525

msg = EmailMessage()
msg["From"] = "test@example.com"
msg["To"] = "you@example.com"
msg["Subject"] = "URGENT: Please review"

# This line is the body, testing urgency logic
msg.set_content(
    "URGENT: action required within 24 hours.\n"
    "Your account will be suspended if you do not respond immediately.\n"
    "\n"
    "This is only a test message for the training gateway."
)

with smtplib.SMTP(GATEWAY_HOST, GATEWAY_PORT) as s:
    s.send_message(msg)

print("Sent urgent test email to gateway.")
