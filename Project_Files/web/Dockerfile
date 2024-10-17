FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
ENV REDIS_KEY_PREFIX="threat_responder:"
CMD ["python", "app.py"]