FROM python:3.11-slim
RUN pip install --no-cache-dir scapy numpy scikit-learn pandas
WORKDIR /app
COPY . .
CMD ["python", "anomaly_detector.py"]
