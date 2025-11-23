from flask import Flask, request
import json
import datetime
import os
import requests
import re

app = Flask(__name__)

# Environment variables set in docker-compose
LOGDIR = os.getenv("LOG_DIR", "/logs")
PUSHOVER_TOKEN = os.getenv("PUSHOVER_TOKEN")
PUSHOVER_USER = os.getenv("PUSHOVER_USER")

os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, "webhook.log")

SEVERITY_MAP = {
    "INFO": -1,
    "NOTICE": 0,
    "WARNING": 0,
    "ERROR": 1,
    "CRITICAL": 1,
    "ALERT": 2,
    "EMERGENCY": 2,
}

def log(msg):
    timestamp = datetime.datetime.now().isoformat()
    line = f"[{timestamp}] {msg}\n"
    print(line, end="")
    with open(LOGFILE, "a") as f:
        f.write(line)

def extract_severity(text):
    text_upper = text.upper()
    for sev in SEVERITY_MAP.keys():
        if sev in text_upper:
            return sev
    return "NOTICE"  # default when none detected

def extract_hostname(text):
    # Looks for "TrueNAS @ hostname"
    match = re.search(r"TrueNAS @ ([A-Za-z0-9._-]+)", text)
    if match:
        return match.group(1)
    return "TrueNAS"

@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "").strip()

        hostname = extract_hostname(text)
        severity = extract_severity(text)
        priority = SEVERITY_MAP.get(severity, 0)

        # Clean formatting: remove repeated newlines and extra spaces
        clean_message = re.sub(r"\n\s*\n", "\n", text).strip()

        log(f"Incoming alert from {hostname} with severity {severity}")
        log(f"Message: {clean_message}")

        # Build Pushover payload
        payload = {
            "token": PUSHOVER_TOKEN,
            "user": PUSHOVER_USER,
            "message": clean_message,
            "title": f"TrueNAS Alert ({severity}) @ {hostname}",
            "priority": priority,
        }

        # Emergency alerts require retry/expire
        if priority == 2:
            payload["retry"] = 30   # resend every 30 sec
            payload["expire"] = 1800  # stop after 30 minutes

        # Send to Pushover
        r = requests.post("https://api.pushover.net/1/messages.json", data=payload)

        if r.status_code != 200:
            log(f"Pushover error: {r.text}")
            return {"status": "error", "details": r.text}, 400

        log("Pushover alert sent successfully")
        return {"status": "ok"}, 200

    except Exception as e:
        log(f"Exception: {str(e)}")
        return {"status": "error", "exception": str(e)}, 500
