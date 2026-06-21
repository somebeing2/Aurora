from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class AuditEvent:
    timestamp_utc: str
    agent_name: str
    input_summary: str
    output_summary: str
    risk_score_0_100: int
    confidence_0_1: float
    metadata: Dict[str, Any]


def _log_path() -> Path:
    p = os.getenv("AURORA_LOG_PATH", "aurora/data/logs/audit_log.jsonl")
    return Path(p)


def append_audit_event(event: AuditEvent) -> None:
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


def now_utc_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def summarize_obj(obj: Any, max_chars: int = 900) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    s = s.replace("\n", " ")
    if len(s) > max_chars:
        return s[: max_chars - 3] + "..."
    return s


def log_agent_decision(
    *,
    agent_name: str,
    prf_project_name: str,
    input_payload: Any,
    output_payload: Any,
    risk_score_0_100: int,
    confidence_0_1: float,
    domain: Optional[str] = None,
) -> None:
    event = AuditEvent(
        timestamp_utc=now_utc_iso(),
        agent_name=agent_name,
        input_summary=summarize_obj(input_payload),
        output_summary=summarize_obj(output_payload),
        risk_score_0_100=risk_score_0_100,
        confidence_0_1=confidence_0_1,
        metadata={"project": prf_project_name, "domain": domain},
    )
    append_audit_event(event)
