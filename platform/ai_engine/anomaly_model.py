from sklearn.ensemble import IsolationForest
import joblib

class AnomalyModel:

    def __init__(self):
     self.model = IsolationForest(contamination=0.2, random_state=42)
    def train(self, X):
     self.model.fit(X)

    print ("model trained and saved")


    def predict(self, X):
     return self.model.predict(X)

    def save(self, path="model.pkl"):
     joblib.dump(self.model, path)

    def load(self, path="model.pkl"):
     self.model = joblib.load(path)


