# AURORA – Autonomous Unified Risk & Oversight Review Agent

AURORA is a production-grade multi-agent AI platform for **enterprise IT governance**, **CISA-aligned audit**, and **pre-implementation software project risk review**.

It evaluates a Project Request Form (PRF) across:

- Legal Risk
- Regulatory Compliance Risk
- Data Protection & Privacy Risk (DPEP)
- AML Risk
- IT Security Risk
- Governance & SDLC Control Risk

AURORA uses:

- **CrewAI** for multi-agent orchestration
- **Ollama** for local or remote open-source LLM inference (default: `mistral`)
- **RAG (LangChain + ChromaDB)** over regulatory circulars/policies
- **Streamlit** dashboard for interactive analysis, audit evidence review, and executive visuals
- **MCP server** to expose agents as callable tools for external orchestrators

## Architecture

- `aurora/models/` – Canonical schemas (PRF input, structured risk outputs)
- `aurora/rag/` – Ingestion + vector store + retrieval used by every agent
- `aurora/governance/` – Audit logging, confidence scoring, hallucination/vagueness checks, explainability
- `aurora/agents/` – Domain agents + aggregator + executive reporting agent
- `aurora/app/` – Streamlit dashboard + heatmap + report viewer
- `aurora/main.py` – CLI runner

## Prerequisites

- Python 3.11+
- Ollama installed and running (local) or reachable (remote)

```bash
ollama serve
ollama pull mistral
```

If you use a remote Ollama instance, ensure it is reachable from this machine:

```bash
curl -fsS http://<OLLAMA_HOST>:11434/api/tags
```

## Setup

Recommended:

```bash
./run.sh setup
```

Manual:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Configuration

AURORA reads configuration from `.env`.

Key variables:

- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`
- `OLLAMA_EMBED_MODEL`
- `CHROMA_PERSIST_DIR`

Notes:

- `OLLAMA_BASE_URL` can be either:
  - `http://host:11434`
  - `http://host:11434/api/generate`
- AURORA normalizes this internally for the LLM/embeddings clients.

## Add/Update Knowledge Sources (RAG)

Place regulation/policy text files in:

- `aurora/data/circulars/`
- `aurora/data/policies/`

AURORA will build/update a Chroma index on first run.

## Run (CLI)

```bash
./run.sh cli aurora/data/sample_prf.json
```

Outputs:

- JSON report printed to stdout
- Audit trail appended to `aurora/data/logs/audit_log.jsonl`

## Run (Dashboard)

```bash
./run.sh dashboard
```

Dashboard highlights:

- Executive visuals (domain risk chart, findings severity donut when Plotly is installed)
- Live run progress + agent cards
- Dark theme via `.streamlit/config.toml`

## Optional API

```bash
./run.sh api
```

## MCP Server (Agents as Tools)

AURORA includes an MCP server that exposes agents as MCP tools (stdio).

Tools:

- `retrieve_evidence`
- `assess_legal`
- `assess_compliance`
- `assess_aml`
- `assess_it_security`
- `assess_itgc`
- `assess_nist_csf`
- `assess_owasp`
- `assess_cobit`
- `assess_iso`
- `assess_ieee`
- `assess_rbi_governance_super`
- `run_enterprise_audit`

Run:

```bash
python -m aurora.mcp_server
```

## Notes on Governance Controls

- **Deterministic aggregation**: enterprise score is purely computed from domain scores + weights.
- **Evidence-first**: each agent must cite retrieved clauses (top-3) as evidence.
- **Confidence scoring**: derived from retrieval relevance + presence of evidence references.
- **Hallucination/vagueness flags**: heuristic flags for non-evidenced and vague language.
- **Audit trail**: every agent decision is logged with timestamp, inputs/outputs, scores, confidence.

## Disclaimer

This tool provides decision support. Final approval remains with your governance and risk functions.
