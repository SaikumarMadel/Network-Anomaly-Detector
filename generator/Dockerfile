FROM python:3.11-slim
RUN pip install --no-cache-dir scapy numpy requests
WORKDIR /app
COPY . .
CMD ["python", "traffic_generator.py"]
