# Network Traffic Generator + Anomaly Detector

An Intrusion Detection System (IDS) simulator that generates synthetic network traffic (HTTP + port scan bursts), sniffs it in real-time, and detects anomalies using an **Isolation Forest** Machine Learning model — all running inside isolated Docker containers with a live web dashboard.

## Architecture

```
┌─────────────┐         ┌───────────────────────────────────┐
│  Generator   │  HTTP   │         Webserver (Nginx)          │
│  Container   │────────▶│  Decoy target on port 80           │
│              │  + SYN  │                                    │
│  (Scapy +    │  probes │  Also serves the Web UI Dashboard  │
│   Requests)  │         │  at http://localhost:8080           │
└─────────────┘         └───────────┬───────────────────────┘
                                    │ Shared network namespace
                                    │ (Sidecar pattern)
                        ┌───────────▼───────────────────────┐
                        │      Detector Container            │
                        │  • Sniffs all TCP packets          │
                        │  • Extracts features every 30s     │
                        │  • Trains Isolation Forest model    │
                        │  • Writes data.json for dashboard  │
                        │  • Logs anomalies to file           │
                        └────────────────────────────────────┘
```

## Stack
- **Python 3.11**, Scapy (packet crafting/sniffing), scikit-learn (Isolation Forest), Joblib (model persistence)
- **Docker + docker-compose** (isolated bridge network, sidecar pattern)
- **Nginx** (decoy webserver + dashboard host)
- **HTML/CSS/JS** (real-time dark-mode dashboard)

## Quick Start
```bash
docker-compose up --build -d
```
- **Dashboard**: Open `http://localhost:8080` in your browser
- **Generator logs**: `docker-compose logs -f generator`
- **Detector logs**: `docker-compose logs -f detector`

## Security Validation (Nmap Scan Simulation)

You can test the IDS by running an Nmap port scan from inside the Docker network:

```bash
# Single scan (500 ports)
docker run --rm --network network-anomaly-sim_default instrumentisto/nmap -p 1-500 network-anomaly-sim-webserver-1

# Aggressive multi-scan (triggers anomaly detection)
for i in $(seq 1 5); do docker run --rm --network network-anomaly-sim_default instrumentisto/nmap -p 1-1000 -T5 network-anomaly-sim-webserver-1; done
```

### Sample Detection Output
```
Normal:  [322, 85, 3]   | Score: -0.47   ← Baseline HTTP traffic
Normal:  [293, 92, 3]   | Score: -0.47   ← Baseline HTTP traffic
ANOMALY DETECTED! Features: [1644, 629, 4] | Score: -0.59  ← Nmap scan detected!
```

The model caught the Nmap scan because:
- **Requests** spiked from ~300 → 1,644
- **Unique Ports** spiked from ~90 → 629
- A **new source IP** appeared (the Nmap container)

## How the ML Model Works
1. The detector collects TCP packet stats in 30-second sliding windows
2. Three features are extracted: `[request_count, unique_ports, unique_source_ips]`
3. After 10 windows (~5 min), the Isolation Forest trains on the baseline
4. Each subsequent window is scored — deviations from the baseline are flagged as anomalies
5. The trained model is persisted to `data/model.joblib` across restarts

## Project Structure
```
network-anomaly-sim/
├── docker-compose.yml          # 3-service orchestration
├── public/
│   └── index.html              # Real-time IDS dashboard
├── generator/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── traffic_generator.py    # HTTP + port scan traffic
├── detector/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── anomaly_detector.py     # ML-based packet analyzer
├── data/                       # Persistent volume (model + logs)
└── README.md
```

## Future Scope
See [FUTURE_SCOPE.md](FUTURE_SCOPE.md) for planned enhancements, including active mitigation, advanced attack patterns, and enhanced visualization.
