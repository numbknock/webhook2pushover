from flask import Flask, request
import json
import datetime as dt
import os
import re
import requests
import traceback

app = Flask(__name__)

# ---- Environment (from docker-compose) ----
LOGDIR = os.getenv("LOG_DIR", "/logs")
PUSHOVER_TOKEN = os.getenv("PUSHOVER_TOKEN")
PUSHOVER_USER = os.getenv("PUSHOVER_USER")
PUSHOVER_SOUND = os.getenv("PUSHOVER_SOUND")  # optional

os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, "webhook.log")

# TrueNAS severity -> Pushover priority
SEVERITY_MAP = {
    "INFO": -1,
    "NOTICE": 0,
    "WARNING": 0,
    "ERROR": 1,
    "CRITICAL": 1,
    "ALERT": 2,
    "EMERGENCY": 2,
}

ACTION_MAP = {
    "INFO": "No immediate action required.",
    "NOTICE": "No immediate action required.",
    "WARNING": "Inspect soon.",
    "ERROR": "Immediate attention required.",
    "CRITICAL": "Immediate attention required.",
    "ALERT": "URGENT: Immediate action required.",
    "EMERGENCY": "URGENT: Immediate action required.",
}

BORDER = "──────────────────────────────────"


# ----------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------
def log(msg: str):
    """Writes to container stdout AND logfile."""
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def debug(msg: str):
    """Verbose debug-level logging."""
    log(f"[DEBUG] {msg}")


# ----------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------
def extract_hostname(text: str) -> str:
    match = re.search(r"TrueNAS\s*@\s*([A-Za-z0-9._-]+)", text)
    hostname = match.group(1) if match else "TrueNAS"
    debug(f"Extracted hostname: {hostname}")
    return hostname


def extract_severity(text: str) -> str:
    text_upper = text.upper().strip()
    first_line = text_upper.split("\n")[0].strip()

    if "TEST ALERT" in text_upper:
        debug("Detected test alert → severity INFO")
        return "INFO"

    for sev in SEVERITY_MAP.keys():
        if first_line.startswith(sev):
            debug(f"Detected severity prefix: {sev}")
            return sev

    for sev in SEVERITY_MAP.keys():
        if sev in text_upper:
            debug(f"Detected severity embedded in text: {sev}")
            return sev

    debug("No severity found → default NOTICE")
    return "NOTICE"


def clean_message(text: str) -> str:
    debug("Cleaning message formatting...")
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    cleaned = t.strip()
    debug(f"Cleaned message:\n{cleaned}")
    return cleaned


def extract_summary(clean_text: str) -> str:
    lines = [ln.strip() for ln in clean_text.split("\n") if ln.strip()]

    filtered = []
    for ln in lines:
        if re.match(r"TrueNAS\s*@\s*[A-Za-z0-9._-]+", ln):
            continue
        filtered.append(ln)

    if not filtered:
        debug("Summary fallback: Alert received")
        return "Alert received"

    first = filtered[0]
    for sev in SEVERITY_MAP.keys():
        if first.upper().startswith(sev + ":"):
            first = first[len(sev)+1:].strip()
            break

    debug(f"Extracted summary: {first}")
    return first if first else filtered[0]


def format_enterprise(summary: str, severity: str, hostname: str, timestamp_utc: str) -> str:
    action = ACTION_MAP.get(severity, ACTION_MAP["NOTICE"])
    formatted = "\n".join([
        BORDER,
        "ALERT DETAILS",
        BORDER,
        f"Summary:       {summary}",
        f"Severity:      {severity}",
        f"Host:          {hostname}",
        f"Timestamp:     {timestamp_utc} UTC",
        "Source:        TrueNAS → webhook2pushover",
        BORDER,
        f"Take Action:   {action}",
        BORDER,
    ])
    debug("Formatted enterprise message:\n" + formatted)
    return formatted


# ----------------------------------------------------------
# Webhook endpoint
# ----------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    log("Received incoming webhook.")
    try:
        if not PUSHOVER_TOKEN or not PUSHOVER_USER:
            log("ERROR: Missing Pushover credentials.")
            return {"status": "error", "details": "Missing credentials"}, 500

        raw = request.get_json(silent=True) or {}
        raw_text = (raw.get("text") or "").strip()

        debug(f"Raw incoming text:\n{raw_text}")

        cleaned = clean_message(raw_text)
        hostname = extract_hostname(cleaned)
        severity = extract_severity(cleaned)
        priority = SEVERITY_MAP.get(severity, 0)
        summary = extract_summary(cleaned)
        timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        log(f"Parsed alert | host={hostname}, severity={severity}, priority={priority}")
        log(f"Summary: {summary}")

        title = f"TrueNAS Alert • {severity} • {hostname}"
        message = format_enterprise(summary, severity, hostname, timestamp_utc)

        payload = {
            "token": PUSHOVER_TOKEN,
            "user": PUSHOVER_USER,
            "title": title,
            "message": message,
            "priority": priority,
        }

        if PUSHOVER_SOUND:
            payload["sound"] = PUSHOVER_SOUND

        if priority == 2:
            payload["retry"] = 30
            payload["expire"] = 1800

        debug(f"Sending payload to Pushover (sanitized):\n"
              f"title={title}\npriority={priority}")

        r = requests.post("https://api.pushover.net/1/messages.json", data=payload)

        if r.status_code != 200:
            log(f"Pushover ERROR {r.status_code}: {r.text}")
            return {"status": "error", "details": r.text}, 400

        log("Pushover alert sent successfully.")
        return {"status": "ok"}, 200

    except Exception as e:
        log(f"EXCEPTION: {str(e)}")
        debug(traceback.format_exc())
        return {"status": "error", "exception": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
