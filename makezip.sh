#!/usr/bin/env bash
# makezip.sh — Zip the AURORA project excluding .venv and other unwanted artifacts
set -euo pipefail

OUTPUT="AURORA_$(date +%Y%m%d_%H%M%S).zip"

zip -r "$OUTPUT" . \
  --exclude ".venv/*" \
  --exclude "__pycache__/*" \
  --exclude "*/__pycache__/*" \
  --exclude "**/__pycache__/*" \
  --exclude ".git/*" \
  --exclude ".DS_Store" \
  --exclude "aurora/data/chroma/*" \
  --exclude "aurora/data/logs/*" \
  --exclude "*.pyc" \
  --exclude "*.pyo" \
  --exclude "AURORA_*.zip"

echo "Created: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
