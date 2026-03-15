from scapy.all import IP, TCP, send, RandShort
import time
import random
import requests

print("Starting synthetic traffic generator... (HTTP + occasional scans)", flush=True)

TARGET_IP = "127.0.0.1"  # Change to a test target if needed (e.g. local nginx)
TARGET_PORTS = [80, 443, 8080]

def send_http():
    try:
        requests.get(f"http://{TARGET_IP}:{random.choice(TARGET_PORTS)}", timeout=1)
        print("Sent HTTP request", flush=True)
    except:
        pass

def send_port_probe():
    sport = RandShort()
    dport = random.randint(1, 1024)  # Low ports for "scan" feel
    pkt = IP(dst=TARGET_IP)/TCP(sport=sport, dport=dport, flags="S")
    send(pkt, verbose=0)
    print(f"Probed port {dport}", flush=True)

while True:
    if random.random() < 0.8:  # 80% normal HTTP
        send_http()
    else:  # Occasional scan bursts
        for _ in range(random.randint(5, 15)):
            send_port_probe()
            time.sleep(0.05)
    time.sleep(random.uniform(0.5, 2.0))  # Variable delay
