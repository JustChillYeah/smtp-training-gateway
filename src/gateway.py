import asyncio
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from email.parser import BytesParser
from email.policy import default

from aiosmtpd.controller import Controller
import smtplib


SAVE_DIR = Path("evidence")
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 25

DOWNSTREAM_HOST = "127.0.0.1"
DOWNSTREAM_PORT = 1025  # Mailpit SMTP

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
    "trust": {
        "label": "Trust",
        "subject": [
            ("TRU_01", 2, ["notification", "account update", "payment receipt", "this message is to inform you"]),
        ],
        "body": [
            ("TRU_02", 2, ["thank you", "customer services", "do not reply to this email", "for your information"]),
            ("TRU_03", 3, ["log in to view", "review your account", "access online banking", "view message details"]),
        ],
        "threshold": 4,
    },
}

TACTIC_TIPS = {
    "urgency": "Look for deadlines and pressure to act quickly.",
    "fear": "Look for threats (account locked, investigation, harm) that push compliance.",
    "authority": "Look for impersonation of official bodies and 'policy/compliance' language.",
    "reward": "Look for unexpected refunds, prizes, or 'money owed to you' claims.",
    "trust": "Look for familiar tone and routine prompts that lower suspicion."
}

def normalise(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"[^\w\s@:/.-]+", " ", text) # keeps useful chars
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text

URL_RE = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)

HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
ANCHOR_TEXT_RE = re.compile(r"<a\b[^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")

def strip_html(html: str) -> str:
    if not html:
        return ""
    return normalise(TAG_RE.sub(" ", html))

def extract_email_domain(header_value: str) -> str:
    """
    Best-effort domain extraction from headers like:
    From: Name <user@domain.com>
    Reply-To: user@other.com
    """
    if not header_value:
        return ""
    s = header_value.strip()
    m = EMAIL_RE.search(s)
    if not m:
        return ""
    addr = m.group(0)
    return addr.rsplit("@", 1)[1].lower()

def extract_signals(msg, plain_body: str, html_body: str):
    """
    Returns:
      signals: list of tuples (signal_id, weight, detail)
    """
    signals = []

    from_domain = extract_email_domain(msg.get("From", ""))
    reply_to_domain = extract_email_domain(msg.get("Reply-To", ""))

    # Signal 1: Reply-To mismatch 
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        signals.append(("SIG_REPLYTO_MISMATCH", 4, f"{from_domain}->{reply_to_domain}"))

    # Build a combined text view for URL counting
    body_text = normalise(plain_body or "")
    body_html_text = strip_html(html_body or "")
    combined = (body_text + " " + body_html_text).strip()

    # Signal 2: URL presence / URL volume
    urls = URL_RE.findall(combined)
    if len(urls) >= 3:
        signals.append(("SIG_MANY_URLS", 2, f"urls={len(urls)}"))
    elif len(urls) == 2:
        signals.append(("SIG_TWO_URLS", 1, "urls=2"))
    elif len(urls) == 1:
        signals.append(("SIG_HAS_URL", 1, "urls=1"))

    # Signal 3: HTML link text mismatch vs href (simple, explainable)
    # If the visible anchor text contains a domain, but that domain isn't in the href, flag it.
    if html_body:
        hrefs = HREF_RE.findall(html_body)[:15]
        anchor_texts = ANCHOR_TEXT_RE.findall(html_body)[:15]
        for i, href in enumerate(hrefs):
            visible = strip_html(anchor_texts[i]) if i < len(anchor_texts) else ""
            # Visible text might contain a domain like "microsoft.com"
            visible_domains = set(re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", visible))
            if visible_domains:
                href_n = normalise(href)
                if not any(d in href_n for d in visible_domains):
                    signals.append(("SIG_LINKTEXT_MISMATCH", 3, f"visible={list(visible_domains)[0]}"))
                    break

    return signals


def analyse_persuasion(subject: str, body: str):
    s = normalise(subject)
    b = normalise(body)

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
    lines.append("=== PERSUASION CUES DETECTED ===")
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

def build_training_banner_html(detections):
    if not detections:
        return ""

    tactics = ", ".join([d["label"] for d in detections])
    tips = "".join(
        f"<li><strong>{d['label']}:</strong> {TACTIC_TIPS.get(d['tactic'], '')}</li>"
        for d in detections
        if TACTIC_TIPS.get(d["tactic"], "")
    )

    # Subtle html styling.
    return f"""
<div style="
  margin: 0 0 16px 0;
  padding: 12px 14px;
  border: 1px solid #e6d9a8;
  background: #fff9db;
  color: #2b2b2b;
  border-radius: 6px;
  font-family: Arial, Helvetica, sans-serif;
  font-size: 13px;
  line-height: 1.35;">
  <div style="font-weight: 700; margin-bottom: 6px;">Persuasion cues detected</div>
  <div style="margin-bottom: 8px;">
    This email contains persuasion techniques commonly used in phishing. Pause before acting and verify the sender via a trusted channel.
  </div>
  <div style="margin-bottom: 6px;"><strong>Detected tactics:</strong> {tactics}</div>
  {"<div style='margin-top: 8px;'><strong>What to look for:</strong><ul style='margin: 6px 0 0 18px; padding: 0;'>" + tips + "</ul></div>" if tips else ""}
</div>
""".strip()


def inject_banner_into_html(existing_html: str, banner_html: str) -> str:
    if not banner_html:
        return existing_html or ""

    html = existing_html or ""

    lower = html.lower()
    body_idx = lower.find("<body")
    if body_idx != -1:
        # Insert right after the opening <body ...> tag
        open_end = lower.find(">", body_idx)
        if open_end != -1:
            return html[:open_end + 1] + banner_html + html[open_end + 1:]

    # Fallback: prepend if no <body> tag found
    return banner_html + html

ALLOWED_DOMAIN = os.getenv("ALLOWED_DOMAIN", "smtp-gateway-lab.com").lower()

def extract_domain(address: str) -> str:
    # Handles both user@domain and "Name ,user@domain>"
    if not address:
        return ""
    address = address.strip()
    if "<" in address and ">" in address:
        address = address.split("<", 1)[1].split(">", 1)[0].strip()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower()

class TrainingGatewayHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        dom = extract_domain(address)
        if dom != ALLOWED_DOMAIN:
            return "550 5.7.1 Relaying denied"
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 OK"
    

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
            html_body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            html_body = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True) or b""
                            html_body = payload.decode(errors="replace")
                        break
            else:
                if msg.get_content_type() == "text/html":
                    try:
                        html_body = msg.get_content()
                    except Exception:
                        payload = msg.get_payload(decode=True) or b""
                        html_body = payload.decode(errors="replace")

            content_for_detection = plain_body or html_body
            detections = analyse_persuasion(subject or "", content_for_detection or "")

            signals = extract_signals(msg, plain_body or "", html_body or "")
            if signals:
                #log as an explainable header
                msg["X-Training-Signals"] = ", ".join([f"{sid}:{w}:{detail}" for sid, w, detail in signals])[:900]

            if detections:
                if signals and detections:
                    sig_ids = {sid for sid, _, _ in signals}

                    for d in detections:
                        # Reply-To mismatch tends to support authority/trust abuse narratives
                        if "SIG_REPLYTO_MISMATCH" in sig_ids and d["tactic"] in ("authority", "trust"):
                            d["score"] += 1
                            d["hits"].append(("SIG_REPLYTOMISMATCH", "signal", 1))

                            # Link pressure supports "action now" tactics
                            if sig_ids.intersection({"SIG_HAS_URL", "SIG_TWO_URLS", "SIG_MANY_URLS", "SIG_LINKTEXT_MISMATCH"}):
                                if d["tactic"] in ("urgency", "fear", "authority", "reward"):
                                    d["score"] += 1
                                    d["hits"].append(("SIG_LINK_PRESSURE", "signal", 1))
                    
                    #Re-sort if score changed
                    detections.sort(key=lambda x: x["score"], reverse=True)

                msg["X-Training-Gateway"] = "smtp-training-gateway"
                msg["X-Training-Tactics"] = ", ".join([d["tactic"] for d in detections])

                non_trust = [d for d in detections if d["tactic"] != "trust"]
                primary = non_trust[0] if non_trust else detections[0]

                subj = msg.get("Subject", "")
                prefix = f"[Potential phishing: {primary['label']}]"
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
                banner_html = build_training_banner_html(detections)

                def _get_html_from_part(p):
                    try:
                        return p.get_content()
                    except Exception:
                        payload = p.get_payload(decode=True) or b""
                        return payload.decode(errors="replace")
                
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/html":
                            existing_html = _get_html_from_part(part)
                            new_html = inject_banner_into_html(existing_html, banner_html)
                            part.set_content(new_html, subtype="html")
                            break
                else:
                    if msg.get_content_type() == "text/html":
                        try:
                            existing_html = msg.get_content()
                        except Exception:
                            payload = msg.get_payload(decode=True) or b""
                            existing_html = payload.decode(errors="replace")
                        new_html = inject_banner_into_html(existing_html, banner_html)
                        msg.set_content(new_html, subtype="html")

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
                allowed_rcpts = [r for r in envelope.rcpt_tos if extract_domain(r) == ALLOWED_DOMAIN]
                if not allowed_rcpts:
                    print("[DROP] relay attempt (no allowed recipients)")
                    return "250 Message accepted for delivery"
                smtp.sendmail(envelope.mail_from, allowed_rcpts, to_forward)

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
