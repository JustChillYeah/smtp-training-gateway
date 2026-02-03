import asyncio
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from email.parser import BytesParser
from email.policy import default

from aiosmtpd.controller import Controller
import smtplib


SAVE_DIR = Path("evidence")
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 2525

DOWNSTREAM_HOST = "127.0.0.1"
DOWNSTREAM_PORT = 1025  # MailHog SMTP

URGENCY_PATTERNS = [
    "urgent", "immediately", "asap", "action required", "act now",
    "within 24 hours", "within 48 hours", "limited time", "final notice",
    "your account will be", "suspended", "terminated", "locked",
]

def detect_urgency(subject: str, body: str) -> tuple[bool, list[str]]:
    text = f"{subject}\n{body}".lower()
    hits = [p for p in URGENCY_PATTERNS if p in text]
    return (len(hits) > 0), hits

def build_urgency_banner(hits: list[str]) -> str:
    found = ", ".join(hits[:5])
    return (
        "=== TRAINING BANNER: URGENCY / TIME PRESSURE ===\n"
        "This email contains language that creates urgency to push quick action.\n"
        "Common signs: tight deadlines, threats of account restriction, pressure words.\n"
        f"Detected cues: {found}\n"
        "What to do: slow down, verify the sender via a trusted channel, don't click in a rush.\n"
        "=== END TRAINING BANNER ===\n\n"
    )


class TrainingGatewayHandler:
    async def handle_DATA(self, server, session, envelope):
        SAVE_DIR.mkdir(exist_ok=True)

        # Raw RFC822 bytes
        raw_bytes = envelope.original_content if envelope.original_content else envelope.content

        # Store evidence copy
        msg_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = SAVE_DIR / f"{ts}_{msg_id}.eml"
        filename.write_bytes(raw_bytes)

        # Minimal header parse for logging (optional, but useful)
        try:
            msg = BytesParser(policy=default).parsebytes(raw_bytes)
            subject = msg.get("Subject", "")
            message_id = msg.get("Message-ID", "")
        except Exception:
            subject = ""
            message_id = ""

        # Loop prevention: if we've already processed it, just forward as-is
        if msg.get("X-Training-Gateway"):
            to_forward = raw_bytes
            print("[INFO] already processed (X-Training-Gateway present)")
        else:
            # Extract plain text body (best effort)
            plain_body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            plain_body = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True) or b""
                            plain_body = payload.decode(errors="replace")
                        break
            else:
                if msg.get_content_type() == "text/plain":
                    try:
                        plain_body = msg.get_content()
                    except Exception:
                        payload = msg.get_payload(decode=True) or b""
                        plain_body = payload.decode(errors="replace")

            is_urgent, hits = detect_urgency(subject or "", plain_body or "")

            if is_urgent:
                # Add training headers
                msg["X-Training-Gateway"] = "smtp-training-gateway"
                msg["X-Training-Tactic"] = "urgency"

                # Subject tag (avoid duplication)
                subj = msg.get("Subject", "")
                if not subj.startswith("[Training: Urgency]"):
                    if "Subject" in msg:
                        del msg["Subject"]
                    msg["Subject"] = f"[Training: Urgency] {subj}"


                # Prepend banner to plain text body if we found one
                if plain_body:
                    banner = build_urgency_banner(hits)
                    new_body = banner + plain_body

                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                part.set_content(new_body)
                                break
                    else:
                        msg.set_content(new_body)

                print(f"[CLASS] urgency hits={hits}")
            else:
                print("[CLASS] no urgency detected")

            to_forward = msg.as_bytes()

        print(f"[RECV] id={msg_id} from={envelope.mail_from} to={envelope.rcpt_tos}")
        if subject:
            print(f"       subject={subject}")
        if message_id:
            print(f"       message-id={message_id}")
        print(f"       saved={filename}")

        # Forward unchanged to downstream SMTP
        try:
            with smtplib.SMTP(DOWNSTREAM_HOST, DOWNSTREAM_PORT, timeout=15) as smtp:
                smtp.sendmail(envelope.mail_from, envelope.rcpt_tos, to_forward)
            print("[FWD ] forwarded to downstream")
        except Exception as e:
            print(f"[ERR ] forwarding failed: {e}")
            # For prototype: accept the message but log failure.
            # In a prod environment ideally i'd queue and retry.
        return "250 Message accepted for delivery"


def main():
    handler = TrainingGatewayHandler()
    controller = Controller(handler, hostname=LISTEN_HOST, port=LISTEN_PORT, decode_data=False)
    controller.start()
    print(f"Gateway listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Forwarding to downstream {DOWNSTREAM_HOST}:{DOWNSTREAM_PORT} (MailHog)")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
