def explain(row, risk):
    explanation = []



    if row["attack"] == 1:
     explanation.append("Attack detected")

    if row["auth_result"] == 0:
     explanation.append("Authentification failed")

    if row["failed_attempts_24h"] > 5:
     explanation.append("Too many failed attempts")

    if row["latency_ms"] > 150:
     explanation.append("High latency")

    if risk > 50:
     level = "HIGH RISK"

    elif risk > 20:
     level = "MEDIUM RISK"

    else:
     level = "LOW RISK"

    return level, explanation
