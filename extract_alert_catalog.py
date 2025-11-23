# Description: Extracts alert definitions from middlewared alert source files and outputs them as JSON.
# Usage: python3 extract_alert_catalog.py > alert_catalog.json

#!/usr/bin/env python3
import os
import re
import json

ALERT_DIR = "/usr/lib/python3/dist-packages/middlewared/alert/source/"

# Regex patterns
CLASS_DEF = re.compile(r"class\s+([A-Za-z0-9_]+)\(AlertClass\):")
ATTR_TITLE = re.compile(r"title\s*=\s*['\"](.+?)['\"]")
ATTR_LEVEL = re.compile(r"level\s*=\s*AlertLevel\.([A-Z_]+)")
ATTR_CATEGORY = re.compile(r"category\s*=\s*AlertCategory\.([A-Z_]+)")

# Matches:
# text = "..."
# text = ("..." "...")  ← concatenation
# text = """ ... """
TEXT_SINGLE = re.compile(r"text\s*=\s*['\"]([^'\"]+)['\"]")
TEXT_MULTILINE = re.compile(r"text\s*=\s*(?P<quote>'''|\"\"\")(?P<body>.*?)(?P=quote)", re.DOTALL)

alert_catalog = []

def extract_text(block: str):
    """Extract the text=... field including multi-line."""
    # Multi-line triple-quoted
    m = TEXT_MULTILINE.search(block)
    if m:
        return m.group("body").strip()

    # Single-line string
    m = TEXT_SINGLE.search(block)
    if m:
        return m.group(1).strip()

    # Concatenated text=("a" "b"), optional support
    concat = re.findall(r"text\s*=\s*\((.*?)\)", block, re.DOTALL)
    if concat:
        combined = " ".join(re.findall(r"['\"](.+?)['\"]", concat[0]))
        return combined.strip()

    return None

def extract_blocks():
    """Scan all files and extract alert classes + their attributes."""
    for root, dirs, files in os.walk(ALERT_DIR):
        for file in files:
            if not file.endswith(".py"):
                continue

            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Find each alert class
            for class_match in CLASS_DEF.finditer(content):
                class_name = class_match.group(1)
                start_idx = class_match.end()

                # Rough extraction: take everything until next class def or end
                next_class = CLASS_DEF.search(content, start_idx)
                block = content[start_idx: next_class.start() if next_class else len(content)]

                title = None
                m = ATTR_TITLE.search(block)
                if m:
                    title = m.group(1).strip()

                level = None
                m = ATTR_LEVEL.search(block)
                if m:
                    level = m.group(1).strip()

                category = None
                m = ATTR_CATEGORY.search(block)
                if m:
                    category = m.group(1).strip()

                text = extract_text(block)

                alert_catalog.append({
                    "class_name": class_name,
                    "file": file,
                    "title": title,
                    "severity": level,
                    "category": category,
                    "text": text,
                })

extract_blocks()

print(json.dumps(alert_catalog, indent=2))
