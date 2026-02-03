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

RULES = {
    "urgency": {
        "label": "Urgency",
        "subject": [
            ("URG_01", 4, ["urgent", "final notice", "final reminder", "action required"]),
        ],
        "body": [
            ("URG_02", 3, ["as soon as possible", "immediately", "you must", "required to", "act now", "within 24 hours", "within 48 hours"]),
            ("URG_03", 5, ["failure to take action will result", "last opportunity", "final notice", "final reminder"]),
        ],
        "threshold": 4,
    },
    "fear": {
        "label": "Fear",
        "subject": [
            ("FER_01", 5, ["unauthorised access", "identity theft", "criminal investigation", "account at risk"]),
        ],
        "body": [
            ("FER_02", 4, ["failure to do so may result", "may result in", "may delay or prevent access", "will be suspended", "will be locked"]),
            ("FER_03", 3, ["review your account activity", "confirm your information", "provide documentation", "complete a security check"]),
        ],
        "threshold": 4,
    },
    "authority": {
        "label": "Authority",
        "subject": [
            ("AUTH_01", 4, ["hm revenue & customs", "hmrc", "account review department", "customer services", "policy team"]),
        ],
        "body": [
            ("AUTH_02", 3, ["terms of service", "privacy policy", "regulatory requirements", "policy review", "compliance", "guidelines"]),
            ("AUTH_03", 4, ["you are required to", "must", "required to confirm", "remain compliant"]),
        ],
        "threshold": 4,
    },
    "reward": {
        "label": "Reward",
        "subject": [
            ("REW_02", 5, ["congratulations", "winner", "you have been selected", "cash prize"]),
            ("REW_01", 4, ["tax refund", "refund available", "overpayment", "reimbursement"]),
        ],
        "body": [
            ("REW_03", 4, ["small payment", "discounted", "reward card", "provides 100"]),
            ("REW_04", 4, ["beneficiary", "bequest", "funds set aside", "compensation matters"]),
            ("REW_05", 3, ["wire transfer approved", "payment processed", "funds transferred"]),
        ],
        "threshold": 5,
    },
}

TACTIC_TIPS = {
    "urgency": "Look for deadlines and pressure to act quickly.",
    "fear": "Look for threats (account locked, investigation, harm) that push compliance.",
    "authority": "Look for impersonation of official bodies and 'policy/compliance' language.",
    "reward": "Look for unexpected refunds, prizes, or 'money owed to you' claims.",
}

def analyse_persuasion(subject: str, body: str):
    s = (subject or "").lower()
    b = (body or "").lower()

    detections = []
    for tactic, cfg in RULES.items():
        score = 0
        hits = []

        for rule_id, weight, patterns in cfg.get("subject", []):
            if any(p in s for p in patterns):
                score += weight
                hits.append((rule_id, "subject", weight))

        for rule_id, weight, patterns in cfg.get("body", []):
            if any(p in b for p in patterns):
                score += weight
                hits.append((rule_id, "body", weight))

        if score >= cfg["threshold"]:
            detections.append({
                "tactic": tactic,
                "label": cfg["label"],
                "score": score,
                "hits": hits,
            })

    detections.sort(key=lambda d: d["score"], reverse=True)
    return detections

def build_training_banner(detections):
    if not detections:
        return ""

    lines = []
    lines.append("=== TRAINING BANNER: PERSUASION CUES DETECTED ===")
    lines.append("This email contains persuasion techniques commonly used in phishing.")
    lines.append("Pause before acting. Verify the sender via a trusted channel.")
    lines.append("")
    lines.append("Detected tactics:")
    for d in detections:
        lines.append(f"- {d['label']} (score {d['score']})")
    lines.append("")
    lines.append("What to look for:")
    for d in detections:
        tip = TACTIC_TIPS.get(d["tactic"], "")
        if tip:
            lines.append(f"- {d['label']}: {tip}")
    lines.append("")
    lines.append("=== END TRAINING BANNER ===")
    lines.append("")
    return "\n".join(lines)



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

            detections = analyse_persuasion(subject or "", plain_body or "")

            if detections:
                msg["X-Training-Gateway"] = "smtp-training-gateway"
                msg["X-Training-Tactics"] = ", ".join([d["tactic"] for d in detections])

                primary = detections[0]
                subj = msg.get("Subject", "")
                prefix = f"[Training: {primary['label']}]"
                if not subj.startswith(prefix):
                    if "Subject" in msg:
                        del msg["Subject"]
                    msg["Subject"] = f"{prefix} {subj}"

                if plain_body:
                    banner = build_training_banner(detections)
                    new_body = banner + "\n" + plain_body

                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                part.set_content(new_body)
                                break
                    else:
                        msg.set_content(new_body)

                fired = []
                for d in detections:
                    for rule_id, loc, w in d["hits"]:
                        fired.append(f"{rule_id}:{loc}:{w}")
                msg["X-Training-Rules"] = ", ".join(fired)[:900]

                print(f"[CLASS] detected={[d['tactic'] for d in detections]}")
            else:
                print("[CLASS] no tactics detected")

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
    print(f"Forwarding to downstream {DOWNSTREAM_HOST}:{DOWNSTREAM_PORT} (MailPit)")
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
