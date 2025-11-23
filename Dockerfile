FROM python:3.11-slim

WORKDIR /app

COPY app.py .
COPY alert_data/truenas_alert_catalog.json /app/alert_catalog.json

RUN pip install flask requests

ENV ALERT_CATALOG=/app/alert_catalog.json

CMD ["python3", "app.py"]
