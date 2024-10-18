FROM python:3.12
WORKDIR /interface
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY interface.py .
ENV REDIS_KEY_PREFIX="threat_responder:"
CMD ["python", "interface.py"]

