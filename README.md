# Network Traffic Simulator with Real-Time Anomaly Detection

A lightweight, Dockerized tool that simulates realistic network traffic (normal HTTP requests + occasional port scan behavior) and automatically detects suspicious patterns using machine learning.

This project demonstrates practical skills in:
- Low-level networking (packet crafting & sniffing with Scapy)
- Cloud security concepts (anomaly-based threat detection)
- Lightweight AI/ML (unsupervised Isolation Forest)
- Containerization (Docker + docker-compose)
- Python scripting and Git version control

Built independently in under 1 hour using AI assistance for rapid prototyping — not part of any classroom or syllabus work.

## Features

- **Traffic Generator**: Produces benign HTTP GET requests and simulated TCP SYN port scans (reconnaissance-style attacks)
- **Anomaly Detector**: Sniffs live TCP packets, extracts behavioral features (packet rate, unique ports, source diversity), and flags anomalies using Isolation Forest
- **Containerized Setup**: Two services running on host network for real packet sending/receiving
- **Real-time Console Alerts**: Shows normal vs anomalous traffic windows with anomaly scores

## Tech Stack

- Python 3.11
- Scapy (packet crafting & sniffing)
- scikit-learn (Isolation Forest)
- NumPy & Pandas (feature extraction)
- Docker & docker-compose
- Git

## Project Structure
