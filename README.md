# webhook2pushover

Small Flask service that accepts a webhook payload (built for TrueNAS alerts) and forwards a formatted notification to Pushover. Runs in Docker with Gunicorn, logs to stdout and `/logs/webhook.log`, and maps TrueNAS severities to Pushover priorities automatically.

## Warning
- This service is experimental and may change without notice.
- Do not use in production without your own testing.
- Keep your Pushover tokens secret; never commit them.

## How it works
- Exposes a single endpoint: `POST /webhook` with JSON `{ "text": "<alert body>" }`.
- Cleans and parses the incoming text to extract host, severity, summary, and timestamp.
- Converts TrueNAS severity to Pushover priority (`INFO:-1, NOTICE/WARNING:0, ERROR/CRITICAL:1, ALERT/EMERGENCY:2`).
- Bundles low-severity alerts by category and sends ERROR+ items individually, always including full alert text.
- Sends the alert to Pushover with optional sound and retry/expire for priority-2 messages.
- Logs every request/decision to stdout and a rotating log file at `${LOG_DIR:-/logs}/webhook.log`.

## Run with Docker
Build locally:
```sh
docker build -t webhook2pushover .
```
Run:
```sh
docker run -d \
  -p 5001:5001 \
  -e PUSHOVER_TOKEN=your_app_token \
  -e PUSHOVER_USER=your_user_or_group_key \
  -e PUSHOVER_SOUND=pushover \         # optional
  -e LOG_DIR=/logs \                   # optional
  -e PORT=5001 \                       # optional
  -v $(pwd)/logs:/logs \
  --name webhook2pushover \
  webhook2pushover
```
The GitHub Actions workflow builds and pushes `ghcr.io/<repo-owner>/webhook2pushover:latest` on every push to `main`.

## Environment variables
- `PUSHOVER_TOKEN` (required): Your Pushover application token.
- `PUSHOVER_USER` (required): Pushover user or group key to notify.
- `PUSHOVER_SOUND` (optional): Pushover sound name.
- `LOG_DIR` (optional): Directory for `webhook.log` (default `/logs`).
- `PORT` (optional): Port the webhook listens on (default `5001`).

## Send a test
```sh
curl -X POST http://localhost:5001/webhook \
  -H "Content-Type: application/json" \
  -d '{"text": "CRITICAL: Pool degraded on TrueNAS @ nas01"}'
```
You should see logs in the container and in `logs/webhook.log`, and receive a Pushover notification.

## Local development
```sh
python -m venv .venv
. .venv/bin/activate   # or .venv\\Scripts\\activate on Windows
pip install -r app/requirements.txt
python app/app.py      # serves on http://0.0.0.0:5001
```

## Notes
- Only the `text` field of the JSON payload is used; other fields are ignored.
- Priority-2 alerts automatically set `retry=30` seconds and `expire=1800` seconds to satisfy Pushover's emergency policy.

## Known Issues
- Logging is basic and may expose sensitive data; avoid running in production without sanitization.
- No rate limiting: high request volume may overwhelm downstream services.
- Incoming raw webhook bodies are also logged to `webhook_raw.log` in `LOG_DIR`.

## TO DO
- Web interface to manage mappings, enable/disable alerts, manage entry- and endpoints etc. 

