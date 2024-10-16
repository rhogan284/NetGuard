FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY threat_detector.py .
COPY config.yaml /app/config.yaml

RUN mkdir -p /mnt/logs && chmod 777 /mnt/logs

CMD ["python", "threat_detector.py"]