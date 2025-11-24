FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app/ /app/

# Copy the alert catalog JSON into the image
COPY alert_data/truenas_alert_catalog.json /app/alert_catalog.json

EXPOSE 5001

# Run using gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5001} app:app"]
