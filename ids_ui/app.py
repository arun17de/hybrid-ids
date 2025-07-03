from flask import Flask, render_template, jsonify
import subprocess
import os
import signal
import time
import shutil
import tempfile

app = Flask(__name__)

zeek_process = None
ml_process = None
alert_process = None  # Global variable


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start")
def start_services():
    global zeek_process, ml_process

    # Start ML API
    if ml_process is None:
        ml_process = subprocess.Popen(
            ["./tf_env/bin/python3", "./ml_api.py"]
        )
        time.sleep(2)  # Give time for ML API to start

    # Start Zeek
    if zeek_process is None:
        zeek_cmd = "echo '<password>' | sudo -S /usr/local/zeek/bin/zeek -i wlp3s0 ./send_to_model.zeek"                  #wlp3s0 - wifi adapter
        zeek_process = subprocess.Popen(zeek_cmd, shell=True)

    return jsonify({"status": "started 🟢"})

@app.route("/stop")
def stop_services():
    global zeek_process, ml_process

    if zeek_process:
        zeek_process.terminate()
        zeek_process = None

    if ml_process:
        ml_process.terminate()
        ml_process = None

    return jsonify({"status": "stopped ⛔"})

@app.route("/predictions")
def get_predictions():
    log_path = "./predictions.log"
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()[-10:]  # show last 10 predictions
        return jsonify({"predictions": lines})
    except FileNotFoundError:
        return jsonify({"predictions": []})

@app.route("/status")
def get_status():
    global zeek_process, ml_process
    if zeek_process and zeek_process.poll() is None and ml_process and ml_process.poll() is None:
        return jsonify({"status": "Running 🟢"})
    return jsonify({"status": "Stopped ⛔"})


@app.route("/start-scripts")
def start_scripts():
    global alert_process
    global alert_process1
    if alert_process is None:
        zeek_script1 = "echo '<password>' | sudo -S zeekctl deploy"
        alert_process1 = subprocess.Popen(zeek_script1, shell=True)
        zeek_script = "echo '<password>' | sudo -S /usr/local/zeek/bin/zeek -i wlp3s0 ./port-scan.zeek"
        alert_process = subprocess.Popen(zeek_script, shell=True)
    return jsonify({"status": "alert script started"})

@app.route("/stop-scripts")
def stop_scripts():
    global alert_process
    if alert_process:
        alert_process.terminate()
        alert_process = None
    return jsonify({"status": "alert script stopped"})
    
import json
@app.route("/alerts")
def get_alerts():
    alerts = []
    log_path = "/usr/local/zeek/logs/current/notice.log"
    history_path = "alert_history.log"  # This file will store persistent alert history

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            shutil.copyfile(log_path, tmp_file.name)
            tmp_path = tmp_file.name

        with open(tmp_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    ts = obj.get("ts", "")
                    msg = obj.get("msg", "")
                    alert_str = f"[{ts}] {msg}"
                    alerts.append(alert_str)
                except json.JSONDecodeError:
                    continue

        os.unlink(tmp_path)  # Clean up temp file

        # Keep only the latest 10 alerts for display
        alerts = alerts[-10:] if alerts else ["No recent alerts."]

        # Append to alert_history.log (one alert per line)
        with open(history_path, "a") as history_file:
            for alert in alerts:
                history_file.write(alert + "\n")

    except Exception as e:
        alerts = ["NO alerts"]

    return jsonify({"alerts": alerts})
    

    
@app.route("/count")
def count():
    # Path to your Zeek and ML logs
    notice_log_path = "/usr/local/zeek/logs/current/notice.log"
    predictions_log_path = "./predictions.log"
    alert_count = 0
    attack_count = 0
    # Count lines in notice.log
    if os.path.exists(notice_log_path):
        with open(notice_log_path, "r") as f:
            alert_count = sum(1 for _ in f)

    # Count attacks in predictions.log
    s
    if os.path.exists(predictions_log_path):
        with open(predictions_log_path, "r") as f:
            for line in f:
                if "Prediction" in line and 'Prediction: Normal' not in line:
                    attack_count += 1
	
    return jsonify({"alert_count": alert_count, "attack_count": attack_count})
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

