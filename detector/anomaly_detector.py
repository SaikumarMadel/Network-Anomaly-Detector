from scapy.all import AsyncSniffer, IP, TCP
import numpy as np
from sklearn.ensemble import IsolationForest
import time
from collections import defaultdict
import joblib
import os
import atexit
import json

print("Starting anomaly detector...")

# Setup data directory
MODEL_PATH = "/app/data/model.joblib"
LOG_PATH = "/app/data/anomalies.log"
JSON_PATH = "/app/public/data.json"

os.makedirs("/app/data", exist_ok=True)
os.makedirs("/app/public", exist_ok=True)

# Dashboard state
dashboard_data = {
    "status": "training",
    "logs": [],
    "current_window": None
}

def save_json():
    try:
        with open(JSON_PATH, "w") as f:
            json.dump(dashboard_data, f)
    except Exception as e:
        print(f"Error saving JSON: {e}")

# Collect stats every window
WINDOW = 30  # seconds
stats = defaultdict(list)  # timestamp -> list of (src, dport)

def log_anomaly(message):
    print(message)
    with open(LOG_PATH, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        f.write(f"[{timestamp}] {message}\n")

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        dport = pkt[TCP].dport
        stats[int(time.time() // WINDOW)].append((src, dport))

# Start standard sniff. 
# Because network_mode is 'service:webserver', we naturally see all packets hitting the nginx container.
sniff_thread = AsyncSniffer(prn=packet_callback, store=0, filter="tcp")
sniff_thread.start()

model = None
history = []  # list of feature vectors: [req_count, unique_ports, unique_srcs]

if os.path.exists(MODEL_PATH):
    print("Loading existing trained model...")
    model = joblib.load(MODEL_PATH)
else:
    print("No existing model found. Will train a new one after gathering data.")

print("Collecting data for 60s before processing...")
time.sleep(60)

def save_model():
    if model is not None:
        joblib.dump(model, MODEL_PATH)
        print("Model saved on exit.")

atexit.register(save_model)

while True:
    now = int(time.time() // WINDOW)
    # Give the previous window a moment to finish populating
    prev_window = now - 1
    
    if prev_window in stats:
        window_data = stats[prev_window]
        req_count = len(window_data)
        unique_ports = len(set(d for _, d in window_data))
        unique_srcs = len(set(s for s, _ in window_data))

        features = [req_count, unique_ports, unique_srcs]
        history.append(features)

        if len(history) >= 10:  # Need some data to train
            dashboard_data["status"] = "active"
            if model is None:
                print("Training Isolation Forest...")
                X = np.array(history)
                model = IsolationForest(contamination=0.1, random_state=42)
                model.fit(X)
                joblib.dump(model, MODEL_PATH)
                print("Model trained and saved.")
            else:
                pred = model.predict([features])
                score = model.score_samples([features])[0]
                is_anomaly = bool(pred[0] == -1)
                
                dashboard_data["current_window"] = {
                    "requests": req_count,
                    "unique_ports": unique_ports,
                    "unique_ips": unique_srcs,
                    "is_anomaly": is_anomaly
                }
                
                log_entry = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    "features": features,
                    "score": float(score),
                    "is_anomaly": is_anomaly
                }
                dashboard_data["logs"].append(log_entry)
                # Keep last 50 logs
                if len(dashboard_data["logs"]) > 50:
                    dashboard_data["logs"].pop(0)
                    
                save_json()

                if is_anomaly:
                    log_anomaly(f"ANOMALY DETECTED! Features (req_count, unique_ports, unique_srcs): {features} | Score: {score:.2f}")
                else:
                    print(f"Normal: {features} | Score: {score:.2f}")
        else:
            print(f"Gathering baseline data... ({len(history)}/10 windows)")
            dashboard_data["status"] = "training"
            dashboard_data["current_window"] = {
                "requests": req_count,
                "unique_ports": unique_ports,
                "unique_ips": unique_srcs,
                "is_anomaly": False
            }
            save_json()
            
    time.sleep(WINDOW)
