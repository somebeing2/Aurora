from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class COBITFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    cobit_reference: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 5, max = 150
    max_total = 150
    if sum_scores <= 0:
        return 0
    score = int(round((sum_scores / max_total) * 100))
    return max(0, min(100, score))


def _risk_level(score_0_100: int) -> str:
    if score_0_100 >= 85:
        return "Critical"
    if score_0_100 >= 60:
        return "High"
    if score_0_100 >= 30:
        return "Medium"
    return "Low"


def assess_cobit_governance(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    governance_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic COBIT governance alignment review."""

    ref = _evidence_source(evidence)

    findings: List[COBITFinding] = []

    def add(rule_id: str, severity: str, issue: str, cobit_ref: str, rec: str) -> None:
        findings.append(
            COBITFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                cobit_reference=cobit_ref,
                recommendation=rec,
            )
        )

    add(
        "COBIT-G1",
        "HIGH",
        "Not Defined: Governance oversight (EDM) is not documented for the initiative.",
        "EDM (Evaluate, Direct, Monitor)",
        "Define governance oversight, decision rights, and accountable owners (EDM model) prior to approval.",
    )
    add(
        "COBIT-G2",
        "MEDIUM",
        "Not Defined: IT performance KPIs are not defined.",
        "MEA (Monitor, Evaluate, Assess)",
        "Define performance KPIs/OKRs and monitoring cadence aligned to benefits delivery.",
    )
    add(
        "COBIT-R1",
        "HIGH",
        "Not Defined: IT risk register is not defined.",
        "APO (Align, Plan, Organize)",
        "Create an IT risk register with owners, mitigations, and residual risk acceptance.",
    )
    add(
        "COBIT-B1",
        "HIGH",
        "Not Defined: Structured implementation plan is not defined.",
        "BAI (Build, Acquire, Implement)",
        "Define implementation plan including milestones, controls, deliverables, and go-live gates.",
    )
    add(
        "COBIT-M1",
        "HIGH",
        "Not Defined: Monitoring mechanism is not defined.",
        "MEA (Monitor, Evaluate, Assess)",
        "Define monitoring mechanisms (SLIs/SLOs), reporting, and corrective action workflows.",
    )

    sum_scores = sum(f.score for f in findings)
    risk_score = _normalize(sum_scores)

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "COBIT Governance",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "cobit_reference": f.cobit_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic COBIT governance review. Missing governance artifacts are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="COBIT Governance Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="cobit_governance",
    )

    return out


def assess_cobit_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_cobit_governance(prf=prf, evidence=evidence)

    src = _evidence_source(evidence)
    evs: List[EvidenceClause] = []
    if src:
        evs.append(EvidenceClause(source=str(src), excerpt="", relevance_score=None))

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        df_findings.append(
            DomainFinding(
                title=str(f.get("rule_id")),
                description=str(f.get("issue")),
                risk_level=str(f.get("severity")),
                remediation=[str(f.get("recommendation"))],
                evidence=evs,
                explainability=None,
                governance_flags=[],
            )
        )

    return DomainRiskResult(
        domain=RiskDomain.governance_sdlc,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )
