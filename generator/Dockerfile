FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir scapy numpy requests
WORKDIR /app
COPY . .
CMD ["python", "traffic_generator.py"]
