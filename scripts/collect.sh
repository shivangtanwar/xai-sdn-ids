#!/bin/bash
# Collect a labelled dataset: controller in "collect" mode + scenario runner.
#   scripts/collect.sh <run-name> <seed> [episodes] [duration]
# Produces data/raw/features_<run>.csv and data/raw/labels_<run>.csv
set -euo pipefail
cd "$(dirname "$0")/.."

RUN=${1:?run name}
SEED=${2:-0}
EPISODES=${3:-20}
DURATION=${4:-30}

export XAI_IDS_MODE=collect
export XAI_FEATURE_LOG=/app/data/raw/features_${RUN}.csv
rm -f "data/raw/features_${RUN}.csv"

docker compose up -d --force-recreate controller
sleep 5
docker compose run --rm --no-deps mininet \
    python3 traffic/scenarios.py --run "$RUN" --seed "$SEED" \
    --episodes "$EPISODES" --duration "$DURATION"
docker compose stop controller
echo "done: data/raw/features_${RUN}.csv data/raw/labels_${RUN}.csv"
