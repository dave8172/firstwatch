#!/bin/sh
# Send firstwatch captures to an OpenTelemetry Collector as OTLP/JSON log records.
# Usage: ./send.sh <capture.json>...   (collector at $OTLP_ENDPOINT, default http://localhost:4318)
set -e
ENDPOINT="${OTLP_ENDPOINT:-http://localhost:4318}"
for f in "$@"; do
  npx -y firstwatch export otlp "$f" |
    curl -sS -X POST "$ENDPOINT/v1/logs" -H 'Content-Type: application/json' --data-binary @- -o /dev/null -w "$f → %{http_code}\n"
done
