#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"
shift || true

if [[ -z "$cmd" ]]; then
  echo "Usage: ./run.sh {setup|cli|dashboard|api}"
  echo "  setup      Create venv, install deps, copy .env if missing"
  echo "  cli        Run CLI against sample PRF"
  echo "  dashboard  Run Streamlit dashboard"
  echo "  api        Run FastAPI (uvicorn)"
  exit 1
fi

if [[ "$cmd" == "setup" ]]; then
  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip
  pip install -r requirements.txt
  if [[ ! -f .env && -f .env.example ]]; then
    cp .env.example .env
  fi
  echo "Setup complete. Start Ollama separately: 'ollama serve'"
  exit 0
fi

if [[ ! -d .venv ]]; then
  echo "Missing .venv. Run: ./run.sh setup"
  exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate

export PYTHONPATH="${PYTHONPATH:-}:$(pwd)"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"

check_ollama() {
  if command -v curl >/dev/null 2>&1; then
    RAW_OLLAMA_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
    OLLAMA_SERVER_URL="${RAW_OLLAMA_URL}"
    if [[ "${RAW_OLLAMA_URL}" =~ ^https?://[^/]+ ]]; then
      OLLAMA_SERVER_URL="${BASH_REMATCH[0]}"
    fi

    if ! curl -fsS "${OLLAMA_SERVER_URL}/api/tags" >/dev/null 2>&1; then
      echo "Ollama not reachable at ${RAW_OLLAMA_URL}. Start it with: ollama serve"
      return 1
    fi
  fi
  return 0
}

case "$cmd" in
  cli)
    check_ollama || exit 1
    prf_path="aurora/data/sample_prf.json"
    if [[ ${#@} -ge 1 && "${1}" != --* ]]; then
      prf_path="$1"
      shift
    fi
    python -m aurora.main --prf "$prf_path" "$@"
    ;;
  dashboard)
    check_ollama || exit 1
    python -m streamlit run aurora/app/dashboard.py
    ;;
  api)
    check_ollama || exit 1
    python -m uvicorn aurora.api:app --reload
    ;;
  *)
    echo "Unknown command: $cmd"
    exit 1
    ;;
esac
