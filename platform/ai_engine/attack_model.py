"""
attack_model.py  –  Random Forest classifier for IoT attack detection.

Replaces IsolationForest (unsupervised, no attack labels) with a
Random Forest (supervised, trained on labeled attack_type column).

Why Random Forest?
  - Your dataset has 100 000 labeled rows with 4 named attack classes.
  - RF learns the exact pattern of each class (MITM, Replay, Clone, Bruteforce).
  - It returns the predicted class name AND a confidence percentage.
  - IsolationForest cannot do either of those things.
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib


ATTACK_CLASSES = ["None", "MITM", "Replay", "Clone", "Bruteforce"]


class AttackModel:

    def __init__(self):
        # n_estimators=100 is a solid default; class_weight balances
        # the slight imbalance between attack types in your dataset.
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced",
        )
        self.trained = False

    def train(self, X_train, y_train):
        """
        Train the model on the provided training data.
        The train/test split is done in main.py before calling this.

        X_train : DataFrame with 5 feature columns (80% of dataset)
        y_train : Series of attack_type strings ("None", "MITM", etc.)
        """
        self.model.fit(X_train, y_train)
        self.trained = True
        print(f"\nModel trained on {len(X_train)} rows.")

    def evaluate(self, X_test, y_test):
        """
        Prints a classification report on the test set (20%).
        Call this after train() with the held-out test split.
        """
        y_pred = self.model.predict(X_test)
        print("\n=== Classification report (test set — 20% never seen) ===")
        print(classification_report(y_test, y_pred))

    def predict(self, X):
        """
        Returns a list of predicted attack class strings.
        e.g. ["None", "MITM", "None", "Bruteforce", ...]
        """
        return self.model.predict(X)

    def predict_with_confidence(self, X):
        """
        Returns a list of (predicted_class, confidence_percent) tuples.
        Confidence = probability of the winning class × 100.
        e.g. [("MITM", 91.4), ("None", 78.2), ...]
        """
        proba = self.model.predict_proba(X)
        classes = self.model.classes_
        results = []
        for row_proba in proba:
            idx = row_proba.argmax()
            predicted_class = classes[idx]
            confidence = round(row_proba[idx] * 100, 1)
            results.append((predicted_class, confidence))
        return results

    def save(self, path="attack_model.pkl"):
        joblib.dump(self.model, path)
        print(f"Model saved to {path}")

    def load(self, path="attack_model.pkl"):
        self.model = joblib.load(path)
        self.trained = True
        print(f"Model loaded from {path}")
