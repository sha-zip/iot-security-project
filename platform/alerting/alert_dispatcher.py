"""
Alert Dispatcher - Logique centralisée pour l'envoi des alertes.
"""

import os
import logging

from email_alerter import EmailAlerter
from telegram_alerter import TelegramAlerter

logger = logging.getLogger(__name__)

# Seuils d'alerte via variables d'environnement
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "70"))
CRITICAL_THRESHOLD = int(os.environ.get("CRITICAL_THRESHOLD", "85"))


class AlertDispatcher:
    """Dispatch les alertes vers Email et Telegram selon le seuil configuré."""

    def __init__(self):
        self.alert_threshold = ALERT_THRESHOLD
        self.critical_threshold = CRITICAL_THRESHOLD
        self.email_alerter = EmailAlerter()
        self.telegram_alerter = TelegramAlerter()
        logger.info(
            "Alert dispatcher initialisé: seuil=%d, critique=%d",
            self.alert_threshold, self.critical_threshold,
        )

    def dispatch(self, risk_data):
        """
        Évalue le risk score et envoie les alertes si nécessaire.

        Args:
            risk_data: dict avec score, level, reason, event_type, device_id
        """
        score = risk_data.get("score", 0)

        if score < self.alert_threshold:
            return

        logger.warning(
            "Alerte déclenchée: device=%s score=%d level=%s reason=%s",
            risk_data.get("device_id"),
            score,
            risk_data.get("level"),
            risk_data.get("reason"),
        )

        # Envoyer via tous les canaux configurés
        self.email_alerter.send_alert(risk_data)
        self.telegram_alerter.send_alert(risk_data)
