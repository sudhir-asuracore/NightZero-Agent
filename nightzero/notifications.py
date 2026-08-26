import json
import logging
import smtplib
import threading
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from nightzero.models import IncidentRecord

logger = logging.getLogger(__name__)

DEFAULT_NOTIFICATION_SETTINGS: dict[str, Any] = {
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_address": "NightZero Alerts <alerts@nightzero.io>",
        "to_addresses": [],
        "use_tls": True,
    },
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
    },
    "slack": {
        "enabled": False,
        "webhook_url": "",
        "channel": "#sre-incidents",
    },
    "triggers": {
        "on_incident_detected": True,
        "on_awaiting_approval": True,
        "on_pr_approved": True,
    },
}


class NotificationDispatcher:
    """Dispatches multi-channel incident notifications via SMTP, Telegram, and Slack."""

    @staticmethod
    def send_smtp_email(config: dict[str, Any], subject: str, text: str, html: str | None = None) -> tuple[bool, str]:
        host = config.get("smtp_host", "smtp.gmail.com")
        port = int(config.get("smtp_port", 587))
        username = config.get("username", "")
        password = config.get("password", "")
        from_address = config.get("from_address") or username or "alerts@nightzero.io"
        to_addresses = config.get("to_addresses") or []
        if isinstance(to_addresses, str):
            to_addresses = [addr.strip() for addr in to_addresses.split(",") if addr.strip()]
        use_tls = bool(config.get("use_tls", True))

        if not host or not to_addresses:
            return False, "SMTP host and recipient addresses are required"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = ", ".join(to_addresses)

        msg.attach(MIMEText(text, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))

        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=10) as server:
                    if username and password:
                        server.login(username, password)
                    server.sendmail(from_address, to_addresses, msg.as_string())
            else:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    if use_tls:
                        server.starttls()
                    if username and password:
                        server.login(username, password)
                    server.sendmail(from_address, to_addresses, msg.as_string())
            return True, f"Email successfully sent to {', '.join(to_addresses)}"
        except Exception as error:
            logger.error("SMTP error: %s", error)
            return False, f"SMTP dispatch failed: {error}"

    @staticmethod
    def send_telegram_message(config: dict[str, Any], text: str) -> tuple[bool, str]:
        import re
        import urllib.error

        bot_token = str(config.get("bot_token", "")).strip()
        chat_id = str(config.get("chat_id", "")).strip()

        if not bot_token or not chat_id:
            return False, "Telegram bot_token and chat_id are required"

        # Normalize token if full URL or leading prefix was entered
        if "api.telegram.org" in bot_token:
            match = re.search(r"bot([0-9]+:[A-Za-z0-9_-]+)", bot_token)
            if match:
                bot_token = match.group(1)
        elif bot_token.startswith("bot") and ":" in bot_token:
            bot_token = bot_token[3:]

        # Validate that bot_token conforms to Telegram standard format (numbers:letters)
        if " " in bot_token or "/" in bot_token or not re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", bot_token):
            return False, "Invalid Telegram bot token format. Expected format: 123456789:ABCDefGhIjKlmnOpQrStUvWxYz"

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
                if body.get("ok"):
                    return True, "Telegram alert delivered successfully"
                return False, f"Telegram API error: {body.get('description', 'Unknown error')}"
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read().decode("utf-8"))
                desc = body.get("description", str(error))
                if error.code == 404:
                    return False, f"Telegram API error (404 Not Found): Invalid Bot Token '{bot_token[:8]}...'. Please verify the token from @BotFather."
                if error.code == 403:
                    if "bot can't send messages to the bot" in desc.lower():
                        return False, "Telegram API error (403 Forbidden): The Chat ID entered is the bot's own ID. Please enter your personal Telegram user ID (get it from @userinfobot) or a group/channel ID."
                    return False, f"Telegram API error (403 Forbidden): {desc}. Ensure you have opened your bot in Telegram and clicked /start."
                if error.code == 400:
                    return False, f"Telegram API error (400 Bad Request): {desc}. Please ensure Chat ID '{chat_id}' is correct and you have sent /start to the bot."
                return False, f"Telegram API error ({error.code}): {desc}"
            except Exception:
                return False, f"Telegram dispatch failed: HTTP {error.code} {error.reason}"
        except urllib.error.URLError as error:
            return False, f"Telegram network error: {error.reason}"
        except Exception as error:
            logger.error("Telegram error: %s", error)
            return False, f"Telegram dispatch failed: {error}"

    @staticmethod
    def send_slack_webhook(config: dict[str, Any], payload: dict[str, Any]) -> tuple[bool, str]:
        import urllib.error

        webhook_url = str(config.get("webhook_url", "")).strip()
        if not webhook_url:
            return False, "Slack webhook_url is required"

        if not webhook_url.startswith("http://") and not webhook_url.startswith("https://"):
            return False, "Invalid Slack webhook URL. Expected format: https://hooks.slack.com/services/..."

        channel = str(config.get("channel", "")).strip()
        if channel and "channel" not in payload:
            payload["channel"] = channel

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                result = response.read().decode("utf-8")
                if response.status == 200 and result == "ok":
                    return True, "Slack alert delivered successfully"
                return True, f"Slack responded with: {result}"
        except urllib.error.HTTPError as error:
            try:
                err_text = error.read().decode("utf-8")
                return False, f"Slack webhook error ({error.code}): {err_text}"
            except Exception:
                return False, f"Slack webhook failed: HTTP {error.code} {error.reason}"
        except urllib.error.URLError as error:
            return False, f"Slack network error: {error.reason}"
        except Exception as error:
            logger.error("Slack error: %s", error)
            return False, f"Slack webhook dispatch failed: {error}"

    @classmethod
    def test_channel(cls, channel: str, config: dict[str, Any]) -> tuple[bool, str]:
        if channel == "email":
            subject = "⚡ [NightZero Test Alert] SMTP Notification Service Check"
            text = (
                "NightZero SRE Agent Test Alert\n\n"
                "This is a diagnostic test message confirming that SMTP email push alerts are properly configured.\n"
                "When production incidents occur, verified root cause analysis (RCA) and draft PR notifications will be sent to this address."
            )
            html = (
                '<div style="font-family: monospace; background: #111; color: #fff; padding: 24px; border: 1px solid #333; border-radius: 6px;">'
                '<h2 style="color: #38bdf8; margin: 0 0 12px 0;">⚡ NightZero Autonomous SRE Agent</h2>'
                '<p style="color: #cbd5e1; font-size: 14px;">Diagnostic SMTP Notification Test</p>'
                '<p style="color: #94a3b8; font-size: 12px;">This message confirms that your SMTP alert pipeline is operational.</p>'
                '<hr style="border: 0; border-top: 1px solid #333; margin: 16px 0;" />'
                '<span style="color: #34d399; font-weight: bold;">● STATUS: OPERATIONAL</span>'
                '</div>'
            )
            return cls.send_smtp_email(config, subject, text, html)

        if channel == "telegram":
            text = (
                "⚡ *NightZero SRE Agent — Test Alert*\n\n"
                "✅ *Status:* Connection Verified\n"
                "This diagnostic message confirms that your Telegram bot is successfully connected to NightZero.\n"
                "Live root cause analysis and sandbox remediation updates will be posted here."
            )
            return cls.send_telegram_message(config, text)

        if channel == "slack":
            payload = {
                "text": "⚡ *NightZero SRE Agent:* Diagnostic test alert delivered successfully.",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "⚡ NightZero SRE Agent — Test Alert"},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                "✅ *Status: Connection Verified*\n"
                                "Your Slack incoming webhook is operational. NightZero will dispatch alerts for detected incidents, sandbox verification results, and Pull Request approvals."
                            ),
                        },
                    },
                ],
            }
            return cls.send_slack_webhook(config, payload)

        return False, f"Unsupported notification channel: {channel}"

    @classmethod
    def dispatch_incident_notification(
        cls, event_type: str, record: IncidentRecord, settings: dict[str, Any]
    ) -> None:
        """Dispatches incident alerts asynchronously across enabled notification channels."""
        triggers = settings.get("triggers", {})

        if event_type == "detected" and not triggers.get("on_incident_detected", True):
            return
        if event_type == "awaiting_approval" and not triggers.get("on_awaiting_approval", True):
            return
        if event_type == "approved" and not triggers.get("on_pr_approved", True):
            return

        def _async_worker():
            context = record.context
            rca = record.rca
            approval = record.approval or {}

            # 1. Prepare formatted texts
            if event_type == "detected":
                headline = f"🚨 [INCIDENT DETECTED] [{context.severity}] {context.service}"
                summary = f"Incident `{context.incident_id}` detected: {context.title}"
            elif event_type == "awaiting_approval":
                headline = f"⚡ [REMEDIATION READY] [{context.severity}] {context.service} (Awaiting Approval)"
                summary = (
                    f"Incident `{context.incident_id}`: Root cause isolated and sandbox-verified.\n"
                    f"*Root Cause:* {rca.root_cause}\n"
                    f"*Proposed Patch:* `{rca.proposed_patch}`\n"
                    f"*Sandbox:* Tests Passed (Exit Code 0)"
                )
            elif event_type == "approved":
                pr_url = approval.get("pr_url", "https://github.com")
                pr_num = approval.get("pr_number", "PR")
                headline = f"✔ [PULL REQUEST OPENED] [{context.service}] PR #{pr_num}"
                summary = f"Incident `{context.incident_id}` approved by `{approval.get('actor', 'reviewer')}`. Draft Pull Request: {pr_url}"
            else:
                headline = f"ℹ [NIGHTZERO UPDATE] {context.title}"
                summary = f"Status: {context.status.value}"

            dashboard_url = "https://nightzero.web.app"

            # 2. Email Dispatch
            email_cfg = settings.get("email", {})
            if email_cfg.get("enabled"):
                subject = f"{headline} — NightZero AI"
                text_content = f"{headline}\n\n{summary}\n\nReview on Control Panel: {dashboard_url}"
                html_content = (
                    f'<div style="font-family: monospace; background: #0f172a; color: #f8fafc; padding: 24px; border: 1px solid #334155; border-radius: 8px;">'
                    f'<h2 style="color: #38bdf8; margin: 0 0 12px 0;">{headline}</h2>'
                    f'<p style="color: #94a3b8; font-size: 13px; line-height: 1.6;">{summary.replace(chr(10), "<br/>")}</p>'
                    f'<div style="margin-top: 20px;">'
                    f'<a href="{dashboard_url}" style="background: #38bdf8; color: #000; padding: 10px 18px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block;">OPEN CONTROL PANEL ↗</a>'
                    f'</div>'
                    f'</div>'
                )
                cls.send_smtp_email(email_cfg, subject, text_content, html_content)

            # 3. Telegram Dispatch
            tg_cfg = settings.get("telegram", {})
            if tg_cfg.get("enabled"):
                tg_text = (
                    f"*{headline}*\n\n"
                    f"{summary}\n\n"
                    f"[Open Control Panel]({dashboard_url})"
                )
                cls.send_telegram_message(tg_cfg, tg_text)

            # 4. Slack Dispatch
            slack_cfg = settings.get("slack", {})
            if slack_cfg.get("enabled"):
                slack_payload = {
                    "text": headline,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": headline},
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": summary},
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Open Control Panel ↗"},
                                    "url": dashboard_url,
                                    "style": "primary",
                                }
                            ],
                        },
                    ],
                }
                cls.send_slack_webhook(slack_cfg, slack_payload)

        threading.Thread(target=_async_worker, daemon=True).start()
