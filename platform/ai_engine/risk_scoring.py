"""
risk_scoring.py  –  Computes a 0-100 risk score from the RF prediction
                    and raw event features.

Score breakdown (max 100):
    +50  if an attack class was detected (not "None")
    +20  extra if the attack is MITM or Clone (identity-level threats)
    +10  if auth_result = Failure
    +10  if failed_attempts_24h > 5
    +10  if secure_element was NOT used (higher risk: no hardware protection)
"""

# Risk weight for each detected attack class
ATTACK_WEIGHTS = {
    "None":       0,
    "Bruteforce": 40,
    "Replay":     45,
    "Clone":      50,
    "MITM":       50,
}


def compute_risk(row, predicted_attack):
    """
    row              : dict-like with keys auth_result, failed_attempts_24h,
                       secure_element (already numeric 0/1 from feature_extractor)
    predicted_attack : string, e.g. "MITM", "None", "Replay" ...

    Returns an integer risk score in [0, 100].
    """
    risk = 0

    # --- attack class score ---
    risk += ATTACK_WEIGHTS.get(predicted_attack, 40)

    # --- auth failure ---
    # auth_result is 0 (failure) or 1 (success) after feature extraction
    if row.get("auth_result", 1) == 0:
        risk += 10

    # --- repeated failures ---
    try:
        if int(row.get("failed_attempts_24h", 0)) > 5:
            risk += 10
    except (ValueError, TypeError):
        pass

    # --- no secure element (software key = easier to clone/steal) ---
    try:
        if int(row.get("secure_element", 1)) == 0:
            risk += 10
    except (ValueError, TypeError):
        pass

    return min(risk, 100)
