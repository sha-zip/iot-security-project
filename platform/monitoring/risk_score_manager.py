"""
Risk Score Manager - Calcule les risk scores pour tous les types d'événements IoT.
"""


class RiskScoreManager:
    """Calcule le risk score basé sur multiples facteurs de sécurité IoT."""

    # Poids de base par type d'événement
    EVENT_WEIGHTS = {
        "auth_failure": 30,
        "attack_detected": 50,
        "cert_expiry": 40,
        "latency_anomaly": 20,
        "brute_force": 60,
        "se_compromised": 70,
        "cert_revoked": 55,
        "suspicious_behavior": 35,
        "normal_activity": 0,
    }

    def compute_risk(self, log):
        """
        Calcule le risk score pour un événement de log.

        Args:
            log: dict avec les champs de l'événement IoT

        Returns:
            dict avec score, level, reason, event_type, device_id
        """
        score = 0
        reasons = []
        event_type = log.get("event_type", "normal_activity")
        device_id = log.get("device_id", "unknown")

        # Score de base selon le type d'événement
        base = self.EVENT_WEIGHTS.get(event_type, 0)
        score += base
        if base > 0:
            reasons.append(self._event_reason(event_type))

        # Facteur: échec d'authentification
        if log.get("auth_result") == "Failure":
            score += 15
            reasons.append("Échec d'authentification détecté")

        # Facteur: attaque détectée
        attack_type = log.get("attack_type", "None")
        if attack_type not in ("None", "none", "", None):
            score += 25
            reasons.append(f"Attaque détectée: {attack_type}")

        # Facteur: tentatives échouées multiples (brute force)
        failed_attempts = int(log.get("failed_attempts_24h", 0))
        if failed_attempts > 10:
            score += 20
            reasons.append(
                f"Nombre élevé de tentatives échouées: {failed_attempts}"
            )
        elif failed_attempts > 5:
            score += 10
            reasons.append(
                f"Tentatives échouées multiples: {failed_attempts}"
            )

        # Facteur: latence anormale
        latency = float(log.get("latency_ms", 0))
        if latency > 200:
            score += 15
            reasons.append(f"Latence très élevée: {latency:.1f}ms")
        elif latency > 150:
            score += 10
            reasons.append(f"Latence anormale: {latency:.1f}ms")

        # Facteur: secure element non utilisé
        se_used = log.get("secure_element_used", True)
        if isinstance(se_used, str):
            se_used = se_used.lower() in ("true", "1", "yes")
        if not se_used:
            score += 5
            reasons.append("Secure Element non utilisé")

        # Limiter le score entre 0 et 100
        score = max(0, min(score, 100))

        # Déterminer le niveau
        level = self._compute_level(score)

        # Construire l'explication
        if not reasons:
            reasons.append("Activité normale")

        return {
            "score": score,
            "level": level,
            "reason": " | ".join(reasons),
            "event_type": event_type,
            "device_id": device_id,
        }

    def _compute_level(self, score):
        """Détermine le niveau de risque basé sur le score."""
        if score >= 85:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def _event_reason(self, event_type):
        """Retourne une explication en français pour chaque type d'événement."""
        reasons_map = {
            "auth_failure": "Authentification échouée",
            "attack_detected": "Attaque détectée sur le réseau",
            "cert_expiry": "Certificat en cours d'expiration",
            "latency_anomaly": "Latence réseau anormale",
            "brute_force": "Tentatives de brute force détectées",
            "se_compromised": "Secure Element potentiellement compromis",
            "cert_revoked": "Certificat révoqué",
            "suspicious_behavior": "Comportement suspect détecté",
            "normal_activity": "Activité normale",
        }
        return reasons_map.get(event_type, f"Événement: {event_type}")
