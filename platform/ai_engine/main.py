
"""
main.py  –  AI engine entry point.

Pipeline:
    1. Load and transform the CSV of IoT auth logs
    2. Train the Random Forest on labeled data
    3. Run predictions with confidence scores
    4. Compute risk score per event
    5. Generate XAI explanation
    6. Print full report for the admin (also written to InfluxDB via monitoring)

Usage:
    python main.py                        # uses default dataset path
    python main.py path/to/logs.csv       # custom path
"""

import sys
from sklearn.model_selection import train_test_split
from feature_extractor import transform_csv, FEATURE_NAMES
from attack_model import AttackModel
from risk_scoring import compute_risk
from xai_explainer import explain


DEFAULT_CSV = "dataset_iot_secure_element.csv"


def main(csv_path=None):
    if csv_path is None:
        csv_path = DEFAULT_CSV

    # ── 1. Load data ──────────────────────────────────────────────────
    print(f"\nLoading data from: {csv_path}")
    X, y = transform_csv(csv_path)
    print(f"Loaded {len(X)} events  |  features: {FEATURE_NAMES}")
    print(X.head())

    # ── 2. Split: 80% train, 20% test ────────────────────────────────
    # stratify=y keeps attack class proportions equal in both splits
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set : {len(X_train)} rows")
    print(f"Test set     : {len(X_test)} rows (model will NEVER see these during training)")

    # ── 3. Train on 80% only ─────────────────────────────────────────
    model = AttackModel()
    model.train(X_train, y_train)
    model.evaluate(X_test, y_test)   # classification report on unseen 20%
    model.save("attack_model.pkl")

    # ── 4. Predict on the 20% the model has never seen ───────────────
    predictions = model.predict_with_confidence(X_test)

    # ── 5-6. Risk + XAI + report ──────────────────────────────────────
    print("\n=== Per-device event report (test set) ===")
    for i, (row_idx, row) in enumerate(X_test.iterrows()):
        predicted_attack, confidence = predictions[i]
        row_dict = row.to_dict()

        risk = compute_risk(row_dict, predicted_attack)
        level, reasons = explain(row_dict, predicted_attack, confidence, risk)

        print(f"\n--- Event {i} ---")
        print(f"  Predicted attack : {predicted_attack}")
        print(f"  Confidence       : {confidence}%")
        print(f"  Risk score       : {risk}/100")
        print(f"  Risk level       : {level}")
        print(f"  Reasons          :")
        for r in reasons:
            print(f"    • {r}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    main(path)
