def compute_risk(row, anomaly_pred):
    risk = 0
#anomaly detected
    if anomaly_pred == -1:
     risk += 50
#attack
    if row["attack"] == 1:
     risk += 30
#auth error
    if row["auth_result"] == 0:
     risk += 10
#many errors
    if row["failed_attempts_24h"] > 5:
     risk += 10

    return min(risk, 100)

