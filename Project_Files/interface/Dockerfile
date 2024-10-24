FROM python:3.12
WORKDIR /interface
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY interface.py .
COPY templates ./templates
ENV REDIS_KEY_PREFIX="threat_responder:"

RUN pip install docker PyYAML

CMD ["python", "interface.py"]