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
DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, "webhook.log")
RAW_LOGFILE = os.path.join(LOGDIR, "webhook_raw.log")

# ----------------------------------------------------------
# Load TrueNAS Alert Catalog (Shipped Inside Container)
# Expected entry structure:
#   {
#     "class_name": "...",
#     "file": "...",
#     "title": "...",
#     "severity": "WARNING",
#     "category": "SYSTEM",
#     "text": "...."
#   }
# ----------------------------------------------------------
alert_catalog = {}
pattern_index = []  # list of { "regex": re.Pattern, "meta": meta }

def template_to_regex(template: str) -> str:
    """
    Convert a TrueNAS alert text template into a regex that can match bullet lines.
    Replaces variable placeholders with .+? wildcards.
    """
    # Only use first line of template (most bullets are single-line summary)
    first_line = template.splitlines()[0].strip()
    if not first_line:
        first_line = template.strip()

    # Escape everything first
    pat = re.escape(first_line)

    # Replace %-format placeholders like %(name)s or %(count)d
    pat = re.sub(r"%\\\([^)]+\\\)[sd]", r".+?", pat)
    pat = pat.replace("%s", ".+?")
    pat = pat.replace("%d", r"\d+")

    # Replace {name} style placeholders (f-strings or .format)
    pat = re.sub(r"\\\{[^}]+\\\}", ".+?", pat)

    # Allow some flexibility around quotes and spaces
    # (most bullet lines differ only in the variable bits)
    return pat

def build_pattern_index():
    global pattern_index
    pattern_index = []

    for meta in alert_catalog.values():
        text = meta.get("text")
        if not text:
            continue

        try:
            pattern_str = template_to_regex(text)
            if not pattern_str:
                continue
            regex = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
            pattern_index.append({"regex": regex, "meta": meta})
        except re.error:
            # If pattern cannot compile, skip it
            continue

    print(f"[INIT] Built pattern index with {len(pattern_index)} patterns from catalog.")

try:
    with open(ALERT_CATALOG_PATH, "r") as f:
        raw_entries = json.load(f)
        for entry in raw_entries:
            title = entry.get("title")
            if title:
                alert_catalog[title.strip()] = entry
    print(f"[INIT] Loaded {len(alert_catalog)} alert definitions from catalog.")
    build_pattern_index()
except Exception as e:
    print(f"[INIT] ERROR loading alert catalog: {e}")
    alert_catalog = {}
    pattern_index = []

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

BORDER = "=" * 25

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

def log_raw_request(req, raw_body: str):
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    path = req.full_path if hasattr(req, "full_path") else req.path
    start_line = f"{req.method} {path}".rstrip("?")
    headers = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])
    entry = "\n".join([
        f"[{timestamp}] RAW REQUEST",
        start_line,
        headers,
        "",
        raw_body,
        "",
    ])
    try:
        with open(RAW_LOGFILE, "a") as f:
            f.write(entry)
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
# Bullet & Section Parsing (Digest Handling)
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
        if lowered in {"the following alert has been cleared", "the following alerts have been cleared"}:
            section = "cleared"
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
        elif section in ("current", "cleared"):
            current_alerts.append(bullet)
        else:
            unscoped.append(bullet)

    if unscoped:
        if not new_alerts and not current_alerts:
            current_alerts = unscoped
        else:
            current_alerts.extend(unscoped)

    return new_alerts, current_alerts

# ----------------------------------------------------------
# Catalog Matching & Unknown Handling
# ----------------------------------------------------------
def detect_alert_from_catalog_by_pattern(text: str):
    """
    Try to match using pattern_index built from alert 'text' templates.
    """
    for entry in pattern_index:
        if entry["regex"].search(text):
            meta = entry["meta"]
            debug(f"Pattern match for item: resolved to title '{meta.get('title')}'")
            return meta, False
    return None, False

def detect_alert_from_catalog_by_title(clean_text: str):
    """
    Fallback: Try to match incoming text to an official TrueNAS alert title.
    Uses:
      - direct title matching
      - fuzzy similarity match
    """
    # Direct lookup by title substring
    for title, meta in alert_catalog.items():
        if title in clean_text:
            debug(f"Matched catalog alert by title: {title}")
            return meta, False

    # Fuzzy match over titles
    best_title = None
    best_score = 0.0

    for title in alert_catalog.keys():
        score = difflib.SequenceMatcher(None, title.lower(), clean_text.lower()).ratio()
        if score > best_score:
            best_score = score
            best_title = title

    if best_score > 0.65 and best_title:
        log(f"UNKNOWN ALERT: No exact match. Best guess by title: '{best_title}' (score={best_score:.2f})")
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

def resolve_item_meta(item_text: str):
    """
    Resolve an individual bullet line to a catalog entry.
    Order:
      1. Pattern-based match (from 'text' templates)
      2. Title/fuzzy-based match on the line itself
    """
    # 1. Pattern-based
    meta, is_unknown = detect_alert_from_catalog_by_pattern(item_text)
    if meta is not None:
        return meta, False

    # 2. Fallback: title/fuzzy on the item text
    return detect_alert_from_catalog_by_title(item_text)

def classify_alert_item(item_text: str, section: str):
    """
    Resolve a single bullet line against the TrueNAS alert catalog.
    """
    meta, is_unknown = resolve_item_meta(item_text)
    meta = dict(meta)  # copy so we don't mutate global catalog
    meta["original"] = item_text
    meta["is_unknown"] = is_unknown
    meta["section"] = section
    if not meta.get("title"):
        meta["title"] = item_text
    return meta

# ----------------------------------------------------------
# Summary & Severity Helpers
# ----------------------------------------------------------
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

# ----------------------------------------------------------
# Pushover Sending + Enterprise Formatting
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
# Webhook Endpoint (Hybrid Mode C)
# ----------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    log("Received incoming webhook.")

    try:
        if not PUSHOVER_TOKEN or not PUSHOVER_USER:
            log("ERROR: Missing Pushover credentials.")
            return {"status": "error", "details": "Missing pushover credentials"}, 500

        raw_body = request.get_data(cache=True, as_text=True) or ""
        if DEBUG_MODE:
            log_raw_request(request, raw_body)

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
            # High-severity items (ERROR and above) are sent individually (Hybrid C)
            high_items = [
                itm for itm in combined
                if PRIORITY_MAP.get(itm.get("severity", "NOTICE"), -1) >= PRIORITY_MAP["ERROR"]
            ]
            low_items = [itm for itm in combined if itm not in high_items]

            timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            # Send high severity individually
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
            # No digest structure → treat entire message as a single alert
            meta, is_unknown = detect_alert_from_catalog_by_title(cleaned)
            severity = meta.get("severity", "NOTICE")
            category = meta.get("category", "GENERAL")
            summary = build_summary(severity, category, 1)
            timestamp_utc = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            ok = send_pushover_message(summary, severity, category, hostname, timestamp_utc,
                                       new_alerts=[], current_alerts=[], is_unknown=is_unknown)
            responses.append(ok)

        if all(responses):
            return {"status": "ok", "sent": len(responses)}, 200
        return {
            "status": "partial_failure",
            "sent": len([r for r in responses if r]),
            "errors": len([r for r in responses if not r])
        }, 502

    except Exception as e:
        log(f"EXCEPTION: {e}")
        debug(traceback.format_exc())
        return {"status": "error", "exception": str(e)}, 500

# ----------------------------------------------------------
# Run
# ----------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    log("Starting webhook2pushover service...")
    app.run(host="0.0.0.0", port=port)
