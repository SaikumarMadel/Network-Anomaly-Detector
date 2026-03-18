# 🚀 Future Scope & Enhancements

This document outlines potential features and technical improvements planned for the Network Anomaly Simulator.

### 🛡️ Active Mitigation (IPS Features)
- **Automatic IP Blocking:** Implement a feedback loop where the Detector can trigger `iptables` or `nftables` rules on the webserver to block anomalous IPs.
- **Rate Limiting:** Dynamically adjust Nginx rate limits based on detected threat levels.

### 🚦 Advanced Attack Simulations
- **Distributed Denial of Service (DDoS):** Simulate multi-source flooding using a cluster of generator containers.
- **Slowloris Attacks:** Simulate resource exhaustion via slow, persistent TCP connections.
- **Brute Force Detection:** Log failed login attempts to the decoy server and flag burst patterns.

### 📈 Dashboard & Visualization
- **Historical Trends:** Add time-series charts (using Chart.js) to visualize traffic shifts over minutes or hours.
- **Threat Level Gauge:** A real-time UI element showing a "Low" to "Critical" security status.
- **Downloadable Reports:** Ability to export 30-day detection logs as CSV or PDF.

### 🧠 Machine Learning & XAI
- **Explainable AI (XAI):** Add tooltips in the UI explaining *which* feature (high ports, high IP count, etc.) contributed most to an anomaly score.
- **Multi-Model Support:** Allow the user to toggle between different algorithms (e.g., Local Outlier Factor vs. Isolation Forest).
- **Online Learning:** Implement a true online learning model that continuously updates its baseline without full retraining.
