from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class DataGovFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _kw(text: str, words: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def _infer_payments(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _kw(ctx, ["payment", "payments", "transfer", "upi", "imps", "neft", "rtgs", "settlement"]) 


def _infer_cross_border(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _kw(ctx, ["cross-border", "international", "outside india", "offshore"]) 


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 12, max = 360
    max_total = 360
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


def assess_data_governance(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    data_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic Data Governance risk assessment (design stage)."""

    ref = _evidence_source(evidence)
    payments = _infer_payments(prf)
    cross_border = _infer_cross_border(prf)

    findings: List[DataGovFinding] = []

    def add(rule_id: str, severity: str, issue: str, rec: str) -> None:
        findings.append(
            DataGovFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                recommendation=rec,
            )
        )

    # DATA-C1
    if not prf.data_classification:
        add(
            "DATA-C1",
            "HIGH",
            "Not Defined: Formal data classification is not defined.",
            "Classify data (Public/Internal/Confidential/Restricted) and record classification in design artifacts.",
        )

    # DATA-C2
    add(
        "DATA-C2",
        "HIGH",
        "Not Defined: Data owner and steward are not documented.",
        "Assign data owner and data steward roles with RACI, approvals, and accountability.",
    )

    # DATA-C3
    add(
        "DATA-C3",
        "HIGH",
        "Not Defined: Data lineage mapping and data flow diagrams are not documented.",
        "Create data lineage/data flow maps including sources, transformations, stores, and consumers.",
    )

    # DATA-C4
    add(
        "DATA-C4",
        "MEDIUM",
        "Not Defined: Data quality validation controls are not defined.",
        "Define data quality controls (validation rules, reconciliation, completeness checks) and monitoring.",
    )

    # DATA-C5
    add(
        "DATA-C5",
        "HIGH",
        "Not Defined: Data retention and archival policy is not defined.",
        "Define retention schedule, archival strategy, legal holds, and secure deletion procedures.",
    )

    # DATA-C6
    if prf.customer_data_involved:
        add(
            "DATA-C6",
            "CRITICAL",
            "Not Defined: Lawful basis for processing customer data is not documented.",
            "Document lawful purpose/consent model aligned to DPDP Act 2023 and internal privacy policy.",
        )

    # DATA-C7
    if payments and cross_border:
        add(
            "DATA-C7",
            "CRITICAL",
            "Not Defined: Payment data appears in scope and cross-border/offshore processing is indicated without India localization clarity.",
            "Confirm payment data localization in India and enforce regional controls; document vendor processing locations.",
        )
    elif payments:
        add(
            "DATA-C7",
            "CRITICAL",
            "Not Defined: Payment data localization is not explicitly confirmed.",
            "Document payment data storage/processing locations and enforce India localization where applicable.",
        )

    # DATA-C8
    if prf.genai_component:
        add(
            "DATA-C8",
            "CRITICAL",
            "Not Defined: AI/ML use is indicated but anonymization controls for training on production data are not defined.",
            "Prohibit training on raw production data; require anonymization/pseudonymization and documented approvals.",
        )

    # DATA-C9
    add(
        "DATA-C9",
        "HIGH",
        "Not Defined: Consent capture mechanism is not defined (where applicable).",
        "Define consent capture, preference management, and evidence retention for consent events.",
    )

    # DATA-C10
    add(
        "DATA-C10",
        "CRITICAL",
        "Not Defined: Data breach notification workflow is not defined.",
        "Define breach notification workflow, ownership, timelines, and communication governance.",
    )

    # DATA-C11
    add(
        "DATA-C11",
        "HIGH",
        "Not Defined: Data inventory / asset register is not defined.",
        "Create data inventory including datasets, classifications, owners, retention, and access paths.",
    )

    # DATA-C12
    add(
        "DATA-C12",
        "MEDIUM",
        "Not Defined: Metadata repository / catalog is not defined.",
        "Implement metadata catalog or repository to maintain dataset definitions and stewardship metadata.",
    )

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 1 and risk_score < 85:
        risk_score = 85

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "Data Governance",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic data governance review. Missing governance artifacts are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="Data Governance Risk Assessment Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="data_governance",
    )

    return out


def assess_data_governance_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_data_governance(prf=prf, evidence=evidence)

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
        domain=RiskDomain.dpep,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )
