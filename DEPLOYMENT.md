# Deployment Notes – SMTP Training Gateway

This document records the steps taken to deploy the SMTP training gateway as a live inbound email relay for a controlled domain.

## Domain Setup

- Domain registered: smtp-gateway-lab.com
- Registrar: Porkbun
- Purpose: receive real internet email for training and evaluation

### DNS Configuration

The following DNS records were configured:

- A record:
  - Host: mail.smtp-gateway-lab.com
  - IP: 188.166.174.122

- MX record:
  - Domain: smtp-gateway-lab.com
  - Target: mail.smtp-gateway-lab.com
  - Priority: 10

All default parking / ALIAS records were removed to avoid MX conflicts.

## Server Provisioning

- VPS provider: DigitalOcean
- OS: Ubuntu 22.04 LTS
- Public IP: 188.166.174.122

The server is used exclusively to host the SMTP gateway.

## Server Preparation

Initial setup steps:

```bash
apt update
apt install -y python3 python3-venv postfix git ufw docker.io
```
Postfix was installed but disabled so the Python gateway could bind directly to port 25.
```
systemctl stop postfix
systemctl disable postfix
```
Firewall configuration:
```
ufw allow 22/tcp
ufw allow 25/tcp
ufw allow 8025/tcp
ufw --force enable
```

## Gateway Deployment
Repository cloned to the VPS:
```
git clone https://github.com/JustChillYeah/smtp-training-gateway.git
```
Python virtual environment created and dependencies installed:
```
python3 -m venv .venv
source .venv/bin/activate
pip install aiosmtpd
```
Gateway configured to listen publicly:
```
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 25
```

## Downstream Mail Handling

Mailpit was deployed using Docker to act as the downstream mailbox:
```
docker run -d --name mailpit --restart unless-stopped \
  -p 1025:1025 -p 8025:8025 axllent/mailpit
```

Mailpit web interface available at: http://188.166.174.122:8025

## Verification
- SMTP listener confirmed on port 25:
```
ss -ltnp | grep ':25'
```
- Real email sent from an external provider to: test@smtp-gateway-lab.com
- Email successfully:
    - Recieved via MX
    - processed by the gateway
    - annotated with training banner
    - forwarded to mailpit
