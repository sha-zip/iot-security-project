"""
Telegram Alerter - Envoie des alertes de sécurité via Telegram Bot API.
"""

import os
import logging
from urllib.request import urlopen, Request
from urllib.parse import quote

logger = logging.getLogger(__name__)

# Configuration via variables d'environnement
TELEGRAM_ENABLED = os.environ.get("TELEGRAM_ENABLED", "false").lower() in (
    "true", "1", "yes",
)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


class TelegramAlerter:
    """Envoie des alertes de sécurité via Telegram."""

    def __init__(self):
        self.enabled = TELEGRAM_ENABLED
        self.bot_token = TELEGRAM_BOT_TOKEN
        self.chat_id = TELEGRAM_CHAT_ID

        if self.enabled and (not self.bot_token or not self.chat_id):
            logger.warning(
                "Telegram alerter activé mais token ou chat_id manquant"
            )
            self.enabled = False

        if self.enabled:
            logger.info("Telegram alerter initialisé: chat_id=%s", self.chat_id)

    def send_alert(self, risk_data):
        """
        Envoie une alerte via Telegram.

        Args:
            risk_data: dict avec score, level, reason, event_type, device_id
        """
        if not self.enabled:
            return

        message = self._format_alert(risk_data)

        try:
            encoded_msg = quote(message)
            url = (
                f"https://api.telegram.org/bot{self.bot_token}/"
                f"sendMessage?chat_id={self.chat_id}"
                f"&text={encoded_msg}&parse_mode=Markdown"
            )
            req = Request(url, method="GET")
            with urlopen(req, timeout=10) as response:  # noqa: S310
                if response.status == 200:
                    logger.info(
                        "Alerte Telegram envoyée: device=%s level=%s",
                        risk_data["device_id"], risk_data["level"],
                    )
                else:
                    logger.warning(
                        "Telegram API réponse inattendue: %s",
                        response.status,
                    )
        except Exception:
            logger.exception("Erreur lors de l'envoi de l'alerte Telegram")

    def _format_alert(self, risk_data):
        """Formate l'alerte pour Telegram (Markdown)."""
        level_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        emoji = level_emoji.get(risk_data["level"], "⚪")

        return (
            f"{emoji} *Alerte Sécurité IoT*\n\n"
            f"*Niveau:* {risk_data['level']}\n"
            f"*Score:* {risk_data['score']}/100\n"
            f"*Device:* `{risk_data['device_id']}`\n"
            f"*Type:* {risk_data['event_type']}\n"
            f"*Raison:* {risk_data['reason']}"
        )
