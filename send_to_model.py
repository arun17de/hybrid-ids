import requests
import sys
import json
from datetime import datetime


if len(sys.argv) != 2:
    print("Usage: python3 send_to_model.py <feature_string>")
    sys.exit(1)

features = sys.argv[1]

try:
    response = requests.post("http://localhost:5001/predict", json={"features": features})
    result = response.json()
    
    # Log to predictions.log
    with open("./predictions.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Prediction: {result['prediction']}\n")

except Exception as e:
    '''with open("./predictions.log", "a") as f:
        f.write(f"Error: {str(e)}\n")'''
