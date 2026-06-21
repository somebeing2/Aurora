from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class RBIGovFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    rbi_reference: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _kw(text: str, words: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def _infer_payments(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _kw(ctx, ["payment", "payments", "transfer", "upi", "imps", "neft", "rtgs", "settlement"]) 


def _infer_offshore(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _kw(ctx, ["outside india", "offshore", "cross-border", "international"]) 


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 6, max = 180
    max_total = 180
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


def assess_rbi_governance_super(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    rbi_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic RBI IT Governance & Cyber Risk review (design stage)."""

    ref_src = _evidence_source(evidence) or "RAG_NOT_PROVIDED"
    payments = _infer_payments(prf)
    offshore = _infer_offshore(prf)

    findings: List[RBIGovFinding] = []

    def add(rule_id: str, severity: str, issue: str, ref: str, rec: str) -> None:
        findings.append(
            RBIGovFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                rbi_reference=ref,
                recommendation=rec,
            )
        )

    add(
        "RBI-GOV1",
        "HIGH",
        "Not Defined: Board approval/oversight is not documented for the initiative.",
        ref_src,
        "Document Board/IT Steering approval, decision rights, and accountable owners prior to approval.",
    )
    add(
        "RBI-GOV2",
        "HIGH",
        "Not Defined: IT risk assessment aligned to RBI IT governance expectations is not documented.",
        ref_src,
        "Perform and document IT risk assessment (inherent/residual), control mapping, and sign-offs.",
    )
    add(
        "RBI-CY1",
        "HIGH",
        "Not Defined: Cyber resilience testing (e.g., DR drills, resilience validation) is not documented.",
        ref_src,
        "Define cyber resilience testing plan, scope, frequency, success criteria, and evidence artifacts.",
    )
    add(
        "RBI-OUT1",
        "CRITICAL",
        "Not Defined: Vendor audit rights (bank/RBI/regulators) are not evidenced in outsourcing arrangements.",
        ref_src,
        "Ensure outsourcing contracts include audit rights, access to records, and regulatory cooperation clauses.",
    )

    if payments and offshore:
        add(
            "RBI-DATA1",
            "CRITICAL",
            "Not Defined: Payment data appears in scope and offshore/cross-border hosting is indicated without India localization confirmation.",
            ref_src,
            "Ensure payment data is stored/processed in India and document data localization controls and cloud region enforcement.",
        )
    else:
        add(
            "RBI-DATA1",
            "CRITICAL",
            "Not Defined: Payment data localization confirmation is not documented (India-only storage/processing).",
            ref_src,
            "Explicitly document payment data storage/processing locations and enforce India localization where applicable.",
        )

    add(
        "RBI-REP1",
        "CRITICAL",
        "Not Defined: RBI reporting workflow for cyber/security incidents and regulatory reporting is not defined.",
        ref_src,
        "Define RBI reporting workflow, ownership, timelines, and evidence artifacts; align to incident management process.",
    )

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 1 and risk_score < 90:
        risk_score = 90

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(_evidence_source(evidence) is not None))
    )

    out = {
        "domain": "RBI IT Governance & Cyber Risk",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "rbi_reference": f.rbi_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic RBI governance/cyber risk review. Missing artifacts are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="RBI IT Governance & Cyber Risk Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="rbi_governance_super",
    )

    return out


def assess_rbi_governance_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_rbi_governance_super(prf=prf, evidence=evidence)

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
        domain=RiskDomain.compliance,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )
