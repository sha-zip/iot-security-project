
from feature_extractor import transform_csv
from anomaly_model import AnomalyModel
from risk_scoring import compute_risk
from xai_explainer import explain

def main():

#charger les donnes
    data = transform_csv("logs.csv")

    print ("Features bien charge")
    print (data.head())

#modele
    model = AnomalyModel()
    model.train(data)
    preds = model.predict(data)

#tester chaque ligne
    for i, row in data.iterrows():


     risk = compute_risk(row, preds[i])
     level, explanation = explain(row, risk)

     print (f"\nDevice {i}")
     print (f"Risk Score: {risk}")
     print (f"Level: {level}")
     print (f"Reasons: {explanation}")

if __name__ == "__main__":
    main()


