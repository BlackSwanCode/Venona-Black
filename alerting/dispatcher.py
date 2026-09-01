import aiohttp
import asyncio
import logging

logger = logging.getLogger("dorker.alerting")


class AlertDispatcher:
    def __init__(self, config: dict):
        self.config = config

    async def send_alert(self, alert_type: str, title: str, details: str, severity: str):
        """Route l'alerte vers les canaux configurés."""
        color_map = {"LOW": "info", "MEDIUM": "warning", "HIGH": "danger", "CRITICAL": "danger"}
        color = color_map.get(severity, "info")

        tasks = []
        if self.config.get("SLACK_WEBHOOK_URL"):
            tasks.append(self._send_slack(title, details, color))
        if self.config.get("TELEGRAM_BOT_TOKEN") and self.config.get("TELEGRAM_CHAT_ID"):
            tasks.append(self._send_telegram(title, details, severity))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, title: str, details: str, color: str):
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 Dorker Pro Alert: {title}",
                "text": details,
                "ts": int(__import__('time').time())
            }]
        }
        async with aiohttp.ClientSession() as session:
            await session.post(self.config["SLACK_WEBHOOK_URL"], json=payload)

    async def _send_telegram(self, title: str, details: str, severity: str):
        token = self.config["TELEGRAM_BOT_TOKEN"]
        chat_id = self.config["TELEGRAM_CHAT_ID"]
        emoji = "🔴" if severity in ["HIGH", "CRITICAL"] else "🟡"
        text = f"{emoji} *{title}*\n\n{details}"
        url = f"https://api.telegram.org/bot{token}/sendMessage"

        async with aiohttp.ClientSession() as session:
            await session.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"})
