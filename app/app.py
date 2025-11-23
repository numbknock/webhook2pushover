from flask import Flask, request
import json
import datetime as dt
import os
import re
import requests
import traceback
import difflib

app = Flask(__name__)

# ----------------------------------------------------------
# Environment (from docker-compose)
# ----------------------------------------------------------
LOGDIR = os.getenv("LOG_DIR", "/logs")
PUSHOVER_TOKEN = os.getenv("PUSHOVER_TOKEN")
PUSHOVER_USER = os.getenv("PUSHOVER_USER")
PUSHOVER_SOUND = os.getenv("PUSHOVER_SOUND")  # optional
ALERT_CATALOG_PATH = os.getenv("ALERT_CATALOG", "/app/alert_catalog.json")

os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, "webhook.log")

# ----------------------------------------------------------
# Load TrueNAS Alert Catalog (Shipped Inside Container)
# ----------------------------------------------------------
alert_catalog = {}

try:
    with open(ALERT_CATALOG_PATH, "r") as f:
        for entry in json.load(f):
            title = entry.get("title")
            if title:
                alert_catalog[title.strip()] = entry
    print(f"[INIT] Loaded {len(alert_catalog)} alert definitions from catalog.")
except Exception as e:
    print(f"[INIT] ERROR loading alert catalog: {e}")
    alert_catalog = {}

# ----------------------------------------------------------
# Pushover Priority Mapping
# ----------------------------------------------------------
PRIORITY_MAP = {
    "INFO": -1,
    "NOTICE": -1,
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
# Logging Helpers
# ----------------------------------------------------------
def log(msg: str):
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def debug(msg: str):
    log(f"[DEBUG] {msg}")


# ----------------------------------------------------------
# Parsing Helpers
# ----------------------------------------------------------
def extract_hostname(text: str) -> str:
    m = re.search(r"TrueNAS\s*@\s*([A-Za-z0-9._-]+)", text)
    hostname = m.group(1) if m else "TrueNAS"
    debug(f"Extracted hostname: {hostname}")
    return hostname


def clean_message(text: str) -> str:
    debug("Cleaning message formatting...")
    t = text.replace("\r", "\n")
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    cleaned = t.strip()
    debug(f"Cleaned message:\n{cleaned}")
    return cleaned


# ----------------------------------------------------------
# Bullet extraction
# ----------------------------------------------------------
def extract_bullets(clean_text: str):
    bullets = []
    for line in clean_text.split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith("* "):
            bullets.append(s[2:].strip())
        elif s.startswith("- "):
            bullets.append(s[2:].strip())
        elif s.startswith("• "):
            bullets.append(s[2:].strip())
    return bullets


# ----------------------------------------------------------
# UNKNOWN ALERT HANDLING WITH FUZZY MATCH
# ----------------------------------------------------------
def detect_alert_from_catalog(clean_text: str):
    """
    Try to match incoming text to an official TrueNAS alert title.
    Uses:
      - direct title matching
      - fuzzy similarity match
    """
    # Direct lookup
    for title, meta in alert_catalog.items():
        if title in clean_text:
            debug(f"Matched catalog alert: {title}")
            return meta, False

    # Fuzzy match
    best_title = None
    best_score = 0.0

    for title in alert_catalog.keys():
        score = difflib.SequenceMatcher(None, title.lower(), clean_text.lower()).ratio()
        if score > best_score:
            best_score = score
            best_title = title

    # If fuzzy match is decent, treat as "near match"
    if best_score > 0.65:
        log(f"UNKNOWN ALERT: No exact match. Best guess: '{best_title}' (score={best_score:.2f})")
        return {
            "title": f"Unknown Alert (closest: {best_title})",
            "severity": "NOTICE",
            "category": "GENERAL",
        }, True

    # Fully unknown
    log("UNKNOWN ALERT: No match in catalog, severity default NOTICE")
    return {
        "title": "Unknown Alert",
        "severity": "NOTICE",
        "category": "GENERAL",
    }, True


# ----------------------------------------------------------
# Summary extraction
# ----------------------------------------------------------
def extract_summary(clean_text: str) -> str:
    lines = [ln.strip() for ln in clean_text.split("\n") if ln.strip()]
    for ln in lines:
        if not ln.lower().startswith("truenas @"):
            debug(f"Extracted summary: {ln}")
            return ln
    return "Alert received"


# ----------------------------------------------------------
# Enterprise formatting
# ----------------------------------------------------------
def format_enterprise(summary: str, severity: str, hostname: str, category: str, timestamp_utc: str):
    action = ACTION_MAP.get(severity, "Review system status.")
    section_category = category.capitalize() if category else "General"

    formatted = "\n".join([
        BORDER,
        "ALERT DETAILS",
        BORDER,
        f"Summary:       {summary}",
        f"Severity:      {severity}",
        f"Category:      {section_category}",
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
# Webhook Endpoint
# ----------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    log("Received incoming webhook.")

    try:
        if not PUSHOVER_TOKEN or not PUSHOVER_USER:
            log("ERROR: Missing Pushover credentials.")
            return {"status": "error", "details": "Missing pushover credentials"}, 500

        raw = request.get_json(silent=True) or {}
        text_raw = (raw.get("text") or "").strip()

        debug(f"Raw incoming text:\n{text_raw}")

        # Clean input text
        cleaned = clean_message(text_raw)

        hostname = extract_hostname(cleaned)
        bullets = extract_bullets(cleaned)

        # Determine alert type
        meta, is_unknown = detect_alert_from_catalog(cleaned)

        severity = meta.get("severity", "NOTICE")
        category = meta.get("category", "GENERAL")
        summary = meta.get("title") or extract_summary(cleaned)

        # Better summary when bullets exist
        if bullets:
            summary = f"{summary} ({len(bullets)} items)"

        timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        priority = PRIORITY_MAP.get(severity, 0)

        log(f"Parsed alert | host={hostname}, severity={severity}, category={category}, priority={priority}")
        log(f"Summary: {summary}")

        # Title for pushover
        title = f"TrueNAS • {severity} • {hostname}"
        if is_unknown:
            title = "TrueNAS • UNKNOWN ALERT"

        # Build message
        message = format_enterprise(summary, severity, hostname, category, timestamp_utc)

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

        debug(f"Sending payload to Pushover:\n"
              f"title={title}\npriority={priority}")

        r = requests.post("https://api.pushover.net/1/messages.json", data=payload)

        if r.status_code != 200:
            log(f"Pushover ERROR {r.status_code}: {r.text}")
            return {"status": "error", "details": r.text}, 400

        log("Pushover alert sent successfully.")
        return {"status": "ok"}, 200

    except Exception as e:
        log(f"EXCEPTION: {e}")
        debug(traceback.format_exc())
        return {"status": "error", "exception": str(e)}, 500


# ----------------------------------------------------------
# Run
# ----------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
    log("Starting webhook2pushover service...")
    