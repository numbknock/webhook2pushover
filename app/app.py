from flask import Flask, request
import json
import datetime
import os

app = Flask(__name__)

LOGDIR = os.getenv("LOG_DIR", "/app/logs")
os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, "webhook.log")

def log(msg):
    timestamp = datetime.datetime.now().isoformat()
    line = f"[{timestamp}] {msg}\n"
    print(line, end="")
    with open(LOGFILE, "a") as f:
        f.write(line)

@app.route("/webhook", methods=["POST"])
def webhook():
    log("----- Incoming Webhook -----")

    # Log headers
    log("Headers:")
    for k, v in request.headers.items():
        log(f"  {k}: {v}")

    # Log body
    try:
        data = request.get_json(silent=True)
        if data is not None:
            log("JSON body:")
            log(json.dumps(data, indent=2))
        else:
            log("Raw body:")
            log(request.data.decode("utf-8", errors="replace"))
    except Exception as e:
        log(f"Error parsing body: {e}")

    log("----- End Webhook -----\n")

    return {"status": "ok"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
