"""
xai_explainer.py  –  Generates a human-readable explanation for the admin.

Takes the feature row, the predicted attack class, its confidence %,
and the computed risk score, and returns:
    level       : "HIGH RISK" / "MEDIUM RISK" / "LOW RISK"
    explanation : list of plain-English reason strings
"""


def explain(row, predicted_attack, confidence, risk):
    """
    row              : dict-like (numeric features from feature_extractor)
    predicted_attack : string e.g. "MITM"
    confidence       : float, e.g. 91.4  (percent)
    risk             : int 0-100

    Returns (level, explanation_list)
    """
    explanation = []

    # --- attack class reason ---
    if predicted_attack != "None":
        explanation.append(
            f"Attack detected: {predicted_attack} (confidence {confidence}%)"
        )

    # --- authentication failure ---
    if row.get("auth_result", 1) == 0:
        explanation.append("Authentication failed")

    # --- too many failures ---
    try:
        attempts = int(row.get("failed_attempts_24h", 0))
        if attempts > 5:
            explanation.append(
                f"Too many failed attempts in last 24h ({attempts})"
            )
    except (ValueError, TypeError):
        pass

    # --- high latency (possible MITM / network interception) ---
    try:
        latency = float(row.get("latency_ms", 0))
        if latency > 150:
            explanation.append(
                f"Abnormally high handshake latency ({latency:.0f} ms) "
                "— possible interception"
            )
    except (ValueError, TypeError):
        pass

    # --- no secure element ---
    try:
        if int(row.get("secure_element", 1)) == 0:
            explanation.append(
                "Secure Element not used — private key stored in software, "
                "vulnerable to cloning"
            )
    except (ValueError, TypeError):
        pass

    # --- clean event ---
    if not explanation:
        explanation.append("No anomaly detected — normal authentication event")

    # --- risk level ---
    if risk >= 70:
        level = "HIGH RISK"
    elif risk >= 30:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return level, explanation
