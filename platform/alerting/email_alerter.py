"""
Email Alerter - Envoie des alertes de sécurité par email via SMTP.
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

# Configuration via variables d'environnement
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "false").lower() in (
    "true", "1", "yes",
)
EMAIL_SMTP_SERVER = os.environ.get("EMAIL_SMTP_SERVER", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
EMAIL_FROM = os.environ.get("EMAIL_FROM", "alerts@iot-security.local")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS = os.environ.get("EMAIL_RECIPIENTS", "")


class EmailAlerter:
    """Envoie des alertes de sécurité par email."""

    def __init__(self):
        self.enabled = EMAIL_ENABLED
        self.smtp_server = EMAIL_SMTP_SERVER
        self.smtp_port = EMAIL_SMTP_PORT
        self.from_addr = EMAIL_FROM
        self.password = EMAIL_PASSWORD
        self.recipients = [
            r.strip()
            for r in EMAIL_RECIPIENTS.split(",")
            if r.strip()
        ]

        if self.enabled and not self.recipients:
            logger.warning(
                "Email alerter activé mais aucun destinataire configuré"
            )
            self.enabled = False

        if self.enabled:
            logger.info(
                "Email alerter initialisé: %s -> %s",
                self.smtp_server, self.recipients,
            )

    def send_alert(self, risk_data):
        """
        Envoie une alerte par email.

        Args:
            risk_data: dict avec score, level, reason, event_type, device_id
        """
        if not self.enabled:
            return

        subject = (
            f"[IoT Security] Alerte {risk_data['level']} - "
            f"Device {risk_data['device_id']}"
        )

        body = self._format_alert(risk_data)

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.recipients)
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.password:
                    server.login(self.from_addr, self.password)
                server.sendmail(
                    self.from_addr, self.recipients, msg.as_string()
                )

            logger.info(
                "Alerte email envoyée: device=%s level=%s",
                risk_data["device_id"], risk_data["level"],
            )
        except Exception:
            logger.exception("Erreur lors de l'envoi de l'alerte email")

    def _format_alert(self, risk_data):
        """Formate l'alerte en HTML."""
        level_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
        }
        color = level_colors.get(risk_data["level"], "#6c757d")

        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: {color};">
                ⚠️ Alerte Sécurité IoT - {risk_data['level']}
            </h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong>Device ID</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {risk_data['device_id']}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong>Risk Score</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {risk_data['score']}/100
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong>Niveau</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;
                               color: {color}; font-weight: bold;">
                        {risk_data['level']}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong>Type</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {risk_data['event_type']}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong>Raison</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {risk_data['reason']}
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
