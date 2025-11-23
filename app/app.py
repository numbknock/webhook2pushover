# Flask webhook that receives TrueNAS alerts and relays them to Pushover.
from flask import Flask, request
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
PUSHOVER_SOUND = os.getenv("PUSHOVER_SOUND")  # optional global fallback

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

HIGH_SEV = {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}

# ----------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------
_file_log_failed_once = False

def log(msg: str):
    """
    Always prints to stdout (docker logs).
    Also appends to /logs/webhook.log.
    If file logging fails, we'll warn once to stdout.
    """
    global _file_log_failed_once
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    line = f"[{timestamp}] {msg}"
    print(line)

    try:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        if not _file_log_failed_once:
            _file_log_failed_once = True
            print(f"[{timestamp}] [WARN] File logging failed writing to {LOGFILE}: {e}")

def debug(msg: str):
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
    """
    FIXED LOGIC:
    - Test alerts -> INFO
    - Prefer first line prefix 'CRITICAL:' etc
    - Otherwise look for standalone whole-word severity tokens
    - NO substring false positives like 'alerts' -> ALERT
    """
    text_upper = text.upper().strip()
    first_line = text_upper.split("\n")[0].strip()

    if "TEST ALERT" in text_upper:
        debug("Detected test alert → severity INFO")
        return "INFO"

    for sev in SEVERITY_MAP.keys():
        if first_line.startswith(sev + ":") or first_line == sev:
            debug(f"Detected severity prefix: {sev}")
            return sev

    for sev in SEVERITY_MAP.keys():
        pattern = rf"\b{sev}\b"
        if re.search(pattern, text_upper):
            debug(f"Detected severity standalone word: {sev}")
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


def extract_bullets(clean_text: str):
    """
    Extract bullet items from TrueNAS messages.
    Supports:
      * item
      - item
      • item
    Also handles leading indentation.
    """
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
    debug(f"Extracted {len(bullets)} bullet(s)")
    return bullets


def extract_summary_and_items(clean_text: str, severity: str):
    """
    Smart summary for multi-alert payloads.

    Returns:
      summary (str)
      items (list[str])  # bullet items
      kind (str)         # 'new', 'cleared', 'current', 'single'
    """
    text_upper = clean_text.upper()

    items = extract_bullets(clean_text)

    # Kind detection
    kind = "single"
    if "NEW ALERTS:" in text_upper:
        kind = "new"
    elif "HAS BEEN CLEARED" in text_upper or "ALERT HAS BEEN CLEARED" in text_upper:
        kind = "cleared"
    elif "CURRENT ALERTS:" in text_upper:
        kind = "current"

    # Remove "TrueNAS @ host" line from summary selection
    lines = [ln.strip() for ln in clean_text.split("\n") if ln.strip()]
    filtered = []
    for ln in lines:
        if re.match(r"TrueNAS\s*@\s*[A-Za-z0-9._-]+", ln):
            continue
        filtered.append(ln)

    # Summary rules
    if kind == "new":
        if items:
            summary = f"New alerts ({len(items)} item{'s' if len(items)!=1 else ''})"
        else:
            summary = "New alerts"
        return summary, items, kind

    if kind == "cleared":
        if items:
            first = items[0]
            if len(items) == 1:
                summary = f"Alert cleared: {first}"
            else:
                summary = f"Alerts cleared ({len(items)} items): {first}"
        else:
            summary = "Alert cleared"
        return summary, items, kind

    if kind == "current":
        if items:
            summary = f"Current alerts ({len(items)} item{'s' if len(items)!=1 else ''})"
        else:
            summary = "Current alerts"
        return summary, items, kind

    # Not a sectioned multi-alert; if bullets exist, summarize count
    if items:
        first = items[0]
        if len(items) == 1:
            summary = first
        else:
            summary = f"{severity} alerts ({len(items)} items): {first}"
        return summary, items, kind

    # Fallback to first meaningful line
    if not filtered:
        summary = "Alert received"
    else:
        first = filtered[0]
        for sev in SEVERITY_MAP.keys():
            if first.upper().startswith(sev + ":"):
                first = first[len(sev)+1:].strip()
                break
        summary = first or filtered[0]

    return summary, items, kind


def format_enterprise(summary: str, severity: str, hostname: str, timestamp_utc: str, body_lines=None) -> str:
    """
    Enterprise message with optional body_lines (bullets etc).
    """
    action = ACTION_MAP.get(severity, ACTION_MAP["NOTICE"])

    parts = [
        BORDER,
        "ALERT DETAILS",
        BORDER,
        f"Summary:       {summary}",
        f"Severity:      {severity}",
        f"Host:          {hostname}",
        f"Timestamp:     {timestamp_utc} UTC",
        "Source:        TrueNAS → webhook2pushover",
        BORDER,
    ]

    if body_lines:
        parts.append("Details:")
        for b in body_lines:
            parts.append(f"  • {b}")
        parts.append(BORDER)

    parts.extend([
        f"Take Action:   {action}",
        BORDER,
    ])

    formatted = "\n".join(parts)
    debug("Formatted enterprise message built")
    return formatted


def send_pushover(title: str, message: str, priority: int):
    """
    Sends a pushover notification, returns response object.
    """
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

    debug(f"Sending to Pushover: title='{title}', priority={priority}")
    return requests.post("https://api.pushover.net/1/messages.json", data=payload, timeout=10)


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

        # Normalize the text and derive metadata used for routing/priority.
        cleaned = clean_message(raw_text)
        hostname = extract_hostname(cleaned)
        severity = extract_severity(cleaned)
        priority = int(SEVERITY_MAP.get(severity, 0))
        summary, items, kind = extract_summary_and_items(cleaned, severity)
        timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        log(f"Parsed alert | host={hostname}, severity={severity}, priority={priority}, kind={kind}")
        log(f"Summary: {summary}")

        # Option C behavior:
        # - High severity with multiple items -> send one per bullet
        # - Low/normal severity -> group into one
        if items and severity in HIGH_SEV:
            log(f"High severity + {len(items)} items → sending separate notifications")
            sent = 0
            # Track each critical item separately for clearer pager noise.
            for item in items:
                item_summary = item
                title = f"TrueNAS Alert • {severity} • {hostname}"
                message = format_enterprise(item_summary, severity, hostname, timestamp_utc)

                r = send_pushover(title, message, priority)
                if r.status_code == 200:
                    sent += 1
                    log(f"Pushover sent OK for item: {item_summary}")
                else:
                    log(f"Pushover ERROR {r.status_code} for item '{item_summary}': {r.text}")

            return {"status": "ok", "sent": sent, "mode": "separate"}, 200

        # Grouped notification
        if items:
            # Low/normal severity: consolidate to avoid spamming Pushover.
            log(f"Grouping {len(items)} items into one notification")

        title = f"TrueNAS Alert • {severity} • {hostname}"
        message = format_enterprise(summary, severity, hostname, timestamp_utc, body_lines=items if items else None)

        r = send_pushover(title, message, priority)
        if r.status_code != 200:
            log(f"Pushover ERROR {r.status_code}: {r.text}")
            return {"status": "error", "details": r.text}, 400

        log("Pushover alert sent successfully.")
        return {"status": "ok", "mode": "grouped" if items else "single"}, 200

    except Exception as e:
        log(f"EXCEPTION: {str(e)}")
        debug(traceback.format_exc())
        return {"status": "error", "exception": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
