#!/bin/bash
# Closed-loop demo: controller in detect mode + scripted scenario
# (heavy benign transfer, SYN flood, port scan, UDP flood).
# Watch decisions live in another terminal:  docker logs -f xai-controller | grep -E "BLOCK|RATE|ALERT"
#   scripts/demo.sh [detect|monitor]
set -euo pipefail
cd "$(dirname "$0")/.."

export XAI_IDS_MODE=${1:-detect}
export XAI_FEATURE_LOG=/app/data/raw/features_demo.csv
rm -f results/audit_log.jsonl

docker compose up -d --force-recreate controller
sleep 6
docker compose run --rm --no-deps mininet \
    python3 traffic/scenarios.py --demo --run demo --duration 30 --gap 10
echo
echo "=== Decisions (non-NONE) ==="
docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python ml/summarize_audit.py
