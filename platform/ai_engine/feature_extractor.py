import pandas as pd

def extract_features(row):
#failed
    try:
     failed_attempts_24h = int(row.get("failed_attempts_24h", 0))
    except:
     failed_attempts_24h = 0
    try:
     latency_ms = float(row.get("latency_ms", 0))
    except:
     latency_ms = 0.0
#auth result
    auth_res = str(row.get("auth_result","")).strip().lower()
    auth_result = 0 if auth_res == "Failure" else 1
#attack tyoe
    attack_type = str(row.get("attack_type", "")).strip().lower()
    attack = 0 if attack_type == "None" else 1
#secure element
    secure_element_used = str(row.get("secure_element", "")).strip().lower()
    secure_element = 1 if secure_element_used == "TRUE" else 0
#auth methode
    auth_method_map = {
      "Challenge_SE": 1,
      "mTLS_Software": 2,
      "mTLS_SE": 3,
    }
    auth_method_str = str(row.get("auth_method", "")).strip().lower()
    auth_method = auth_method_map.get(auth_method_str, 0)

    return [
      failed_attempts_24h,
      latency_ms,
      auth_result,
      attack,
      secure_element,
      auth_method
   ]

def transform_csv(file_path):
    df = pd.read_csv("logs.csv")
    features = df.apply(extract_features, axis=1)
    feature_names = [
     "failed_attempts_24h",
     "latency_ms",
     "auth_result",
     "attack",
     "secure_element",
     "auth_method",
    ]

    features_df = pd.DataFrame(features.tolist())
    features_df.columns = feature_names

    return features_df



