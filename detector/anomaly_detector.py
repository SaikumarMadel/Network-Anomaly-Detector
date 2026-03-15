from scapy.all import AsyncSniffer, IP, TCP
import numpy as np
from sklearn.ensemble import IsolationForest
import time
import pandas as pd
from collections import defaultdict

print("Starting anomaly detector...", flush=True)

# Collect stats every window
WINDOW = 10  # Reduced to 10 seconds so you see results faster
stats = defaultdict(list)  # timestamp -> list of (src, dport)

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        dport = pkt[TCP].dport
        stats[int(time.time() // WINDOW)].append((src, dport))

sniff_thread = AsyncSniffer(prn=packet_callback, store=0, filter="tcp")  # background sniff
sniff_thread.start()

model = None
history = []  # list of feature vectors: [req_count, unique_ports, unique_srcs]

print("Collecting baseline traffic data for 30s before training...", flush=True)
time.sleep(30)

while True:
    now = int(time.time() // WINDOW)
    # Check the previous window to ensure it's fully complete
    prev_window = now - 1
    if prev_window in stats:
        window_data = stats[prev_window]
        req_count = len(window_data)
        unique_ports = len(set(d for _, d in window_data))
        unique_srcs = len(set(s for s, _ in window_data))

        features = [req_count, unique_ports, unique_srcs]
        history.append(features)

        if len(history) >= 3:  # Need 3 windows of data to train initially
            if model is None:
                print("=========================================", flush=True)
                print("Training Isolation Forest Anomaly Model...", flush=True)
                print("=========================================", flush=True)
                X = np.array(history)
                model = IsolationForest(contamination=0.1, random_state=42)
                model.fit(X)
            else:
                pred = model.predict([features])
                score = model.score_samples([features])[0]
                if pred[0] == -1:
                    print(f"=========================================", flush=True)
                    print(f"🚨 ANOMALY DETECTED! (Likely Port Scan) 🚨", flush=True)
                    print(f"Features [Requests, Ports, IPs]: {features}", flush=True)
                    print(f"Suspicion Score: {score:.2f}", flush=True)
                    print(f"=========================================", flush=True)
                else:
                    print(f"✅ Normal Traffic: {features} | Score: {score:.2f}", flush=True)
                    
        # cleanup old stats to save memory
        keys_to_delete = [k for k in list(stats.keys()) if k < prev_window]
        for k in keys_to_delete:
            del stats[k]

    time.sleep(WINDOW / 2)
