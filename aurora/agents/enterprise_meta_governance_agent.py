from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aurora.agents.residual_risk_agent import compute_residual_risk


def _now_utc_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(round(float(x)))
    except Exception:
        return default


def _extract_score(agent_output: Optional[Dict[str, Any]]) -> int:
    if not agent_output:
        return 0
    for k in ("risk_score", "risk_score_0_100", "score_0_100"):
        if k in agent_output:
            return max(0, min(100, _as_int(agent_output.get(k), 0)))
    return 0


def _extract_findings(agent_output: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not agent_output:
        return []
    f = agent_output.get("findings")
    if isinstance(f, list):
        out: List[Dict[str, Any]] = []
        for item in f:
            if isinstance(item, dict):
                out.append(item)
        return out
    return []


def _is_critical_finding(finding: Dict[str, Any]) -> bool:
    sev = str(finding.get("severity", "")).strip().lower()
    if sev == "critical":
        return True
    score = _as_int(finding.get("score"), 0)
    return score >= 30


def _summarize_top_findings(findings: Sequence[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    scored: List[Tuple[int, str, Dict[str, Any]]] = []
    for f in findings:
        score = _as_int(f.get("score"), 0)
        rid = str(f.get("rule_id", ""))
        scored.append((score, rid, f))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [x[2] for x in scored[:limit]]


def _approval_recommendation(residual_risk_score: int) -> str:
    if residual_risk_score >= 80:
        return "Reject"
    if residual_risk_score >= 55:
        return "Conditional"
    return "Approve"


def aggregate_enterprise_governance(
    *,
    iso_output: Optional[Dict[str, Any]] = None,
    cobit_output: Optional[Dict[str, Any]] = None,
    nist_output: Optional[Dict[str, Any]] = None,
    rbi_output: Optional[Dict[str, Any]] = None,
    owasp_output: Optional[Dict[str, Any]] = None,
    it_security_output: Optional[Dict[str, Any]] = None,
    aml_output: Optional[Dict[str, Any]] = None,
    legal_output: Optional[Dict[str, Any]] = None,
    ieee_output: Optional[Dict[str, Any]] = None,
    residual_risk_output: Optional[Dict[str, Any]] = None,
    maturity_output: Optional[Dict[str, Any]] = None,
    control_effectiveness_override: Optional[float] = None,
) -> Dict[str, Any]:
    """Enterprise Governance Orchestrator (deterministic).

    Accepts agent JSON outputs and aggregates:
    - Enterprise inherent risk (0–100)
    - Enterprise residual risk (0–100)
    - Overall maturity
    - Top 5 critical findings
    - Regulatory exposure index
    - Board-level summary + heatmap + recommendation

    All returned values are JSON-serializable.
    """

    domain_outputs: Dict[str, Optional[Dict[str, Any]]] = {
        "ISO": iso_output,
        "COBIT": cobit_output,
        "NIST": nist_output,
        "RBI": rbi_output,
        "OWASP": owasp_output,
        "IT Security": it_security_output,
        "AML": aml_output,
        "Legal": legal_output,
        "IEEE": ieee_output,
    }

    domain_scores: Dict[str, int] = {k: _extract_score(v) for k, v in domain_outputs.items()}

    # Enterprise inherent risk: average of provided domain risk scores.
    available_scores = [s for s in domain_scores.values() if s > 0]
    enterprise_inherent = int(round(sum(available_scores) / len(available_scores), 0)) if available_scores else 0

    # Residual risk: use provided residual_risk_output if supplied, else compute from inherent and a control effectiveness.
    if residual_risk_output and isinstance(residual_risk_output, dict) and "residual_risk" in residual_risk_output:
        enterprise_residual = max(0, min(100, _as_int(residual_risk_output.get("residual_risk"), 0)))
        ce = _as_float(residual_risk_output.get("control_effectiveness"), 0.0)
        ce = max(0.0, min(1.0, float(round(ce, 2))))
    else:
        ce = float(control_effectiveness_override) if control_effectiveness_override is not None else 0.0
        ce = max(0.0, min(1.0, float(round(ce, 2))))
        rr = compute_residual_risk(inherent_risk=enterprise_inherent, control_effectiveness=ce)
        enterprise_residual = int(rr.get("residual_risk", 0))

    residual_level = "Low"
    if residual_risk_output and isinstance(residual_risk_output, dict) and "risk_level" in residual_risk_output:
        residual_level = str(residual_risk_output.get("risk_level"))
    else:
        residual_level = str(compute_residual_risk(inherent_risk=enterprise_inherent, control_effectiveness=ce).get("risk_level"))

    # Maturity
    overall_maturity_score = 0.0
    overall_maturity_level = "Ad Hoc"
    if maturity_output and isinstance(maturity_output, dict):
        overall_maturity_score = float(round(_as_float(maturity_output.get("average_score"), 0.0), 2))
        overall_maturity_level = str(maturity_output.get("maturity_level", "Ad Hoc"))

    # Findings aggregation
    all_findings: List[Dict[str, Any]] = []
    for out in domain_outputs.values():
        all_findings.extend(_extract_findings(out))

    critical_findings = [f for f in all_findings if _is_critical_finding(f)]
    top5_critical = _summarize_top_findings(critical_findings, limit=5)

    # Regulatory exposure index (focus on regulatory-heavy domains)
    reg_scores = [
        domain_scores.get("RBI", 0),
        domain_scores.get("AML", 0),
        domain_scores.get("Legal", 0),
        domain_scores.get("NIST", 0),
    ]
    reg_scores = [s for s in reg_scores if s > 0]
    regulatory_exposure_index = int(round(sum(reg_scores) / len(reg_scores), 0)) if reg_scores else 0

    recommendation = _approval_recommendation(enterprise_residual)

    heatmap = {
        "domains": [
            {"domain": k, "risk_score": v}
            for k, v in sorted(domain_scores.items(), key=lambda x: (-x[1], x[0]))
        ]
    }

    board_summary = (
        "Enterprise governance aggregation indicates "
        f"Inherent Risk={enterprise_inherent}/100 and Residual Risk={enterprise_residual}/100 ({residual_level}). "
        f"Regulatory Exposure Index={regulatory_exposure_index}/100. "
        f"Overall Maturity={overall_maturity_level} ({overall_maturity_score})."
    )

    executive_summary = {
        "recommendation": recommendation,
        "inherent_risk": enterprise_inherent,
        "residual_risk": enterprise_residual,
        "residual_risk_level": residual_level,
        "regulatory_exposure_index": regulatory_exposure_index,
        "overall_maturity": {"average_score": overall_maturity_score, "maturity_level": overall_maturity_level},
        "top_critical_findings_count": len(critical_findings),
    }

    return {
        "domain": "Enterprise Meta Governance",
        "generated_at_utc": _now_utc_iso(),
        "enterprise_inherent_risk": enterprise_inherent,
        "enterprise_residual_risk": enterprise_residual,
        "enterprise_residual_risk_level": residual_level,
        "control_effectiveness": ce,
        "overall_maturity": {"average_score": overall_maturity_score, "maturity_level": overall_maturity_level},
        "top_5_critical_findings": top5_critical,
        "regulatory_exposure_index": regulatory_exposure_index,
        "board_level_risk_summary": board_summary,
        "executive_summary": executive_summary,
        "heatmap_data": heatmap,
        "approval_recommendation": recommendation,
        "inputs_used": {
            "domain_scores": domain_scores,
            "provided_residual_risk": bool(residual_risk_output),
            "provided_maturity": bool(maturity_output),
        },
    }
