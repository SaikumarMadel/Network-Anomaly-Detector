from scapy.all import IP, TCP, send, RandShort
import time
import random
import requests
import socket

print("Starting synthetic traffic generator... (HTTP + occasional scans)")

# New target is the nginx container in our docker-compose network
TARGET_NAME = "webserver"
TARGET_PORTS = [80] # Nginx default port

# Resolve the hostname to an IP so Scapy can route packets to it
def get_target_ip():
    while True:
        try:
            ip = socket.gethostbyname(TARGET_NAME)
            print(f"Resolved {TARGET_NAME} to IP: {ip}")
            return ip
        except socket.gaierror:
            print(f"Waiting for {TARGET_NAME} to be available...")
            time.sleep(2)

TARGET_IP = get_target_ip()

def send_http():
    try:
        # We target port 80 (nginx). Timeout is short because we expect an immediate response
        requests.get(f"http://{TARGET_NAME}:{random.choice(TARGET_PORTS)}", timeout=1)
        print("Sent HTTP request")
    except Exception as e:
        print(f"HTTP request failed: {e}")

def send_port_probe():
    sport = RandShort()
    dport = random.randint(1, 1024)  # Low ports for "scan" feel
    # Craft a custom SYN packet to an arbitrary port
    pkt = IP(dst=TARGET_IP)/TCP(sport=sport, dport=dport, flags="S")
    send(pkt, verbose=0)
    print(f"Probed port {dport}")

while True:
    if random.random() < 0.7:  # 70% normal HTTP (slightly lower to increase bursts)
        send_http()
    else:  # More frequent and massive scan bursts
        print("--- INITIATING MASSIVE PORT SCAN BURST ---")
        for _ in range(random.randint(30, 60)):
            send_port_probe()
            time.sleep(0.01) # Shoot packets much faster
    time.sleep(random.uniform(0.1, 0.3))  # Aggressive constant traffic
