import pandas as pd


def extract_features(row):
    """
    Converts one raw auth event (dict or DataFrame row) into
    a list of 6 numeric features for the Random Forest model.

    Fields expected from the IoT agent auth event:
        failed_attempts_24h  – how many times this device failed in the last 24h
        latency_ms           – TLS/mTLS handshake duration in milliseconds
        auth_result          – "Success" or "Failure"
        attack_type          – "None", "MITM", "Replay", "Clone", "Bruteforce"
        secure_element_used  – "True" / "False" (whether SoftHSM2 SE was used)
        auth_method          – "Challenge_SE", "mTLS_Software", "mTLS_SE"
    """

    # --- failed attempts (integer) ---
    try:
        failed_attempts_24h = int(row.get("failed_attempts_24h", 0))
    except (ValueError, TypeError):
        failed_attempts_24h = 0

    # --- latency (float ms) ---
    try:
        latency_ms = float(row.get("latency_ms", 0))
    except (ValueError, TypeError):
        latency_ms = 0.0

    # --- auth result: 0 = Failure, 1 = Success ---
    # BUG FIX: input is lowercased before comparison so compare to lowercase
    auth_res = str(row.get("auth_result", "")).strip().lower()
    auth_result = 0 if auth_res == "failure" else 1

    # --- secure element used: 1 = True, 0 = False ---
    # BUG FIX: compare to lowercase "true"
    se_raw = str(row.get("secure_element_used", "")).strip().lower()
    secure_element = 1 if se_raw == "true" else 0

    # --- auth method encoded as integer ---
    auth_method_map = {
        "challenge_se":   1,
        "mtls_software":  2,
        "mtls_se":        3,
    }
    auth_method_str = str(row.get("auth_method", "")).strip().lower()
    auth_method = auth_method_map.get(auth_method_str, 0)

    return [
        failed_attempts_24h,
        latency_ms,
        auth_result,
        secure_element,
        auth_method,
    ]


def extract_label(row):
    """
    Extracts the target label (attack_type) from a row.
    NaN / missing values mean normal traffic → label "None".
    """
    val = row.get("attack_type", None)
    if val is None or (isinstance(val, float)):
        return "None"
    val = str(val).strip()
    return val if val else "None"


FEATURE_NAMES = [
    "failed_attempts_24h",
    "latency_ms",
    "auth_result",
    "secure_element",
    "auth_method",
]


def transform_csv(file_path):
    """
    Reads a CSV of IoT auth logs and returns:
        X  – feature DataFrame (5 columns)
        y  – label Series  (attack_type strings)

    BUG FIX: now uses the file_path parameter instead of hardcoded "logs.csv"
    """
    df = pd.read_csv(file_path)

    features = df.apply(extract_features, axis=1)
    X = pd.DataFrame(features.tolist(), columns=FEATURE_NAMES)

    y = df.apply(extract_label, axis=1)

    return X, y
