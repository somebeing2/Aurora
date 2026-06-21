from __future__ import annotations

import json
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

from aurora.agents.orchestrator import run_full_audit
from aurora.models.prf_schema import ProjectRequestForm


app = FastAPI(title="AURORA API", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    load_dotenv()


@app.post("/audit")
def audit_prf(prf: ProjectRequestForm):
    try:
        report = run_full_audit(prf)
        return report.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
