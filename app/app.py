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
RAW_LOGFILE = os.path.join(LOGDIR, "webhook_raw.log")

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

BORDER = "=" * 58


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


def log_raw_payload(raw_body: str):
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    try:
        with open(RAW_LOGFILE, "a") as f:
            f.write(f"[{timestamp}] {raw_body}\n")
    except Exception:
        pass


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


def parse_alert_sections(clean_text: str):
    """
    TrueNAS combines "New alerts" and "Current alerts" into one message body.
    This breaks them out so we can summarize and prioritize properly.
    """
    new_alerts = []
    current_alerts = []
    unscoped = []
    section = None

    for line in clean_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        lowered = stripped.rstrip(":").lower()
        if lowered in {"new alerts", "new alert"}:
            section = "new"
            continue
        if lowered in {"current alerts", "current alert"}:
            section = "current"
            continue

        bullet = None
        for prefix in ("* ", "- "):
            if stripped.startswith(prefix):
                bullet = stripped[len(prefix):].strip()
                break

        if not bullet:
            continue

        if section == "new":
            new_alerts.append(bullet)
        elif section == "current":
            current_alerts.append(bullet)
        else:
            unscoped.append(bullet)

    if unscoped:
        if not new_alerts and not current_alerts:
            current_alerts = unscoped
        else:
            current_alerts.extend(unscoped)

    return new_alerts, current_alerts


def classify_alert_item(item_text: str, section: str):
    """
    Resolve a single bullet line against the TrueNAS alert catalog.
    Falls back to fuzzy catalog match and then unknown.
    """
    meta, is_unknown = detect_alert_from_catalog(item_text)
    meta = dict(meta)
    meta["original"] = item_text
    meta["is_unknown"] = is_unknown
    meta["section"] = section
    if not meta.get("title"):
        meta["title"] = item_text
    return meta


def summarize_titles(items):
    names = [itm.get("title") or itm.get("original") for itm in items]
    if not names:
        return ""
    summary = ", ".join(names[:3])
    if len(names) > 3:
        summary += f", and {len(names) - 3} more"
    return summary


def highest_severity(items, fallback: str):
    best_severity = fallback
    best_priority = PRIORITY_MAP.get(fallback, 0)
    for itm in items:
        sev = itm.get("severity", fallback)
        prio = PRIORITY_MAP.get(sev, best_priority)
        if prio > best_priority:
            best_priority = prio
            best_severity = sev
    return best_severity


def derive_category(items, fallback: str):
    categories = {itm.get("category") for itm in items if itm.get("category")}
    if not categories:
        return fallback
    if len(categories) == 1:
        return categories.pop()
    return "MULTIPLE"


def build_summary(severity: str, category: str, count: int) -> str:
    sev = (severity or "NOTICE").title()
    cat = (category or "GENERAL").capitalize()
    return f"{sev}: {cat} Alerts ({count})"


def send_pushover_message(summary: str, severity: str, category: str, hostname: str, timestamp_utc: str,
                          new_alerts, current_alerts, is_unknown: bool):
    priority = PRIORITY_MAP.get(severity, 0)
    title = f"TrueNAS | {severity} | {hostname}"
    if is_unknown:
        title = "TrueNAS | UNKNOWN ALERT"

    message = format_enterprise(summary, severity, hostname, category, timestamp_utc,
                                new_alerts=new_alerts, current_alerts=current_alerts)

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
          f"title={title}\npriority={priority}\nsummary={summary}")

    r = requests.post("https://api.pushover.net/1/messages.json", data=payload)
    if r.status_code != 200:
        log(f"Pushover ERROR {r.status_code}: {r.text}")
        return False

    log("Pushover alert sent successfully.")
    return True


# ----------------------------------------------------------
# Enterprise formatting
# ----------------------------------------------------------
def format_enterprise(summary: str, severity: str, hostname: str, category: str, timestamp_utc: str,
                      new_alerts=None, current_alerts=None):
    new_alerts = new_alerts or []
    current_alerts = current_alerts or []
    section_category = category.capitalize() if category else "General"

    lines = [
        BORDER,
        "ALERT DETAILS",
        BORDER,
        f"Summary:       {summary}",
        f"Severity:      {severity}",
        f"Category:      {section_category}",
        f"Host:          {hostname}",
        f"Timestamp:     {timestamp_utc} UTC",
        "Source:        TrueNAS -> webhook2pushover",
        BORDER,
    ]

    if new_alerts:
        lines.append("New Alerts:")
        for itm in new_alerts:
            lines.append(f"- {itm.get('original') or itm.get('title')}")
        lines.append(BORDER)

    if current_alerts:
        lines.append("Current Alerts:")
        for itm in current_alerts:
            lines.append(f"- {itm.get('original') or itm.get('title')}")
        lines.append(BORDER)

    formatted = "\n".join(lines)
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

        raw_body = request.get_data(as_text=True) or ""
        log_raw_payload(raw_body)

        raw = request.get_json(silent=True) or {}
        text_raw = (raw.get("text") or "").strip()

        debug(f"Raw incoming text:\n{text_raw}")

        # Clean input text
        cleaned = clean_message(text_raw)

        hostname = extract_hostname(cleaned)
        new_alerts_raw, current_alerts_raw = parse_alert_sections(cleaned)

        new_alerts = [classify_alert_item(item, "new") for item in new_alerts_raw]
        current_alerts = [classify_alert_item(item, "current") for item in current_alerts_raw]
        combined = new_alerts + current_alerts

        responses = []

        if combined:
            # High-severity items (ERROR and above) are sent individually
            high_items = [itm for itm in combined if PRIORITY_MAP.get(itm.get("severity", "NOTICE"), -1) >= PRIORITY_MAP["ERROR"]]
            low_items = [itm for itm in combined if itm not in high_items]

            timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            for itm in high_items:
                severity = itm.get("severity", "ERROR")
                category = itm.get("category", "GENERAL")
                summary = build_summary(severity, category, 1)
                is_unknown = itm.get("is_unknown", False)
                new_list = [itm] if itm.get("section") == "new" else []
                current_list = [itm] if itm.get("section") != "new" else []
                ok = send_pushover_message(summary, severity, category, hostname, timestamp_utc,
                                           new_list, current_list, is_unknown)
                responses.append(ok)

            # Bundle remaining items by category
            categories = {}
            for itm in low_items:
                categories.setdefault(itm.get("category", "GENERAL"), []).append(itm)

            for cat, items in categories.items():
                severity = highest_severity(items, "NOTICE")
                is_unknown = any(itm.get("is_unknown") for itm in items)
                summary = build_summary(severity, cat, len(items))

                new_list = [itm for itm in items if itm.get("section") == "new"]
                current_list = [itm for itm in items if itm.get("section") == "current"]

                ok = send_pushover_message(summary, severity, cat, hostname, timestamp_utc,
                                           new_list, current_list, is_unknown)
                responses.append(ok)
        else:
            meta, is_unknown = detect_alert_from_catalog(cleaned)
            severity = meta.get("severity", "NOTICE")
            category = meta.get("category", "GENERAL")
            summary = build_summary(severity, category, 1)
            timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            ok = send_pushover_message(summary, severity, category, hostname, timestamp_utc,
                                       new_alerts=[], current_alerts=[], is_unknown=is_unknown)
            responses.append(ok)

        if all(responses):
            return {"status": "ok", "sent": len(responses)}, 200
        return {"status": "partial_failure", "sent": len([r for r in responses if r]), "errors": len([r for r in responses if not r])}, 502

    except Exception as e:
        log(f"EXCEPTION: {e}")
        debug(traceback.format_exc())
        return {"status": "error", "exception": str(e)}, 500


# ----------------------------------------------------------
# Run
# ----------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
    log("Starting webhook2pushover service...")
    


