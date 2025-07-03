from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np
import pickle
from sklearn.preprocessing import StandardScaler
import pandas as pd

app = Flask(__name__)

# Load trained CNN-GRU multi-class model
model = tf.keras.models.load_model("./cnn_gru_conn_dns_ssl_multiclass.keras")

# Load label encoders
with open("./label_encoders.pkl", "rb") as f:
    label_encoders = pickle.load(f)

# Load and fit StandardScaler using training dataset
df = pd.read_csv("./datasets/UNSW_NB15_training-set.csv")
df.drop(columns=["id"], inplace=True)

# Use only selected 8 fields + label
selected_features = [
    'proto', 'service', 'state',       # 'state' = Zeek 'conn_state'
    'dur', 'sbytes', 'dbytes',
    'spkts', 'dpkts',
    'label'
]
df = df[selected_features]

# Encode categorical fields
for col in ['proto', 'service', 'state']:
    df[col] = label_encoders[col].transform(df[col])

# Prepare scaler
X = df.drop(columns=['label']).values.astype(np.float32)
scaler = StandardScaler()
scaler.fit(X)

# Mapping of class index to attack names
class_names = {
    0: "Normal",
    1: "DoS",
    2: "Fuzzers",
    3: "Scanning",
    4: "Backdoor",
    5: "Exploits",
    6: "Generic",
    7: "Shellcode"
}

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json["features"]
        fields = data.split(",")  # Features should be sent as a comma-separated string

        if len(fields) != 8:
            return jsonify({"error": "Invalid number of features. Expected 8 features."}), 400

        # Parse the 8 features in the correct order
        try:
            proto = fields[0]
            service = fields[1]
            state = fields[2]
            dur = float(fields[3])
            sbytes = int(fields[4])
            dbytes = int(fields[5])
            spkts = int(fields[6])
            dpkts = int(fields[7])
        except ValueError as e:
            return jsonify({"error": f"Invalid feature value: {str(e)}"}), 400

        # Encode categorical fields
        try:
            proto = label_encoders['proto'].transform([proto])[0] if proto in label_encoders['proto'].classes_ else -1
            service = label_encoders['service'].transform([service])[0] if service in label_encoders['service'].classes_ else -1
            state = label_encoders['state'].transform([state])[0] if state in label_encoders['state'].classes_ else -1
        except KeyError as e:
            return jsonify({"error": f"Invalid categorical value: {str(e)}"}), 400

        # Build input vector
        x_input = np.array([[proto, service, state, dur, sbytes, dbytes, spkts, dpkts]], dtype=np.float32)

        # Scale and reshape
        x_scaled = scaler.transform(x_input)
        x_scaled = np.expand_dims(x_scaled, axis=2)

        # Predict
        prediction = model.predict(x_scaled)
        
        # Get the predicted class index (highest probability)
        predicted_class_index = np.argmax(prediction, axis=1)[0]

        # Get the predicted class name from the class_names dictionary
        predicted_class_name = class_names.get(predicted_class_index, "Unknown")

        return jsonify({"prediction": predicted_class_name})

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)

