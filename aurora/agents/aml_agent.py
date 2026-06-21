from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class AMLFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    regulatory_reference: Optional[str]
    recommendation: str


_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 30,
}


def _keyword_present(text: str, keywords: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(k.lower() in t for k in keywords)


def _infer_onboarding_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(
        prf.customer_impact,
        ["onboarding", "account opening", "kyc", "cdd", "customer due diligence", "identity verification"],
    )


def _infer_payments_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(
        prf.customer_impact,
        ["payment", "payments", "transfer", "transfers", "remittance", "p2p", "wire"],
    )


def _infer_cross_border_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(prf.customer_impact, ["cross-border", "international", "swift", "remittance"])


def _evidence_reference(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize_score(sum_rule_scores: int) -> int:
    """Normalize to 0-100.

    Deterministic normalization using a fixed maximum across the rulebook.
    Total possible (13 rules) * 30 = 390.
    """

    max_total = 390
    if sum_rule_scores <= 0:
        return 0
    score = int(round((sum_rule_scores / max_total) * 100))
    if score < 0:
        return 0
    if score > 100:
        return 100
    return score


def _risk_level(score_0_100: int) -> str:
    if score_0_100 >= 85:
        return "Critical"
    if score_0_100 >= 60:
        return "High"
    if score_0_100 >= 30:
        return "Medium"
    return "Low"


def assess_aml(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    aml_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic AML assessment.

    Inputs:
    - PRF (validated)
    - Regulatory clauses retrieved via RAG (top-k)
    - Optional internal policy excerpt text

    Output:
    - Strict JSON dict per requested AML agent contract.
    """

    onboarding = _infer_onboarding_in_scope(prf)
    payments = _infer_payments_in_scope(prf)
    cross_border = _infer_cross_border_in_scope(prf)
    ref = _evidence_reference(evidence)

    findings: List[AMLFinding] = []

    def add(rule_id: str, severity: str, issue: str, recommendation: str) -> None:
        findings.append(
            AMLFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity.upper()],
                issue=issue,
                regulatory_reference=ref,
                recommendation=recommendation,
            )
        )

    # CUSTOMER RISK RULES
    if onboarding:
        add(
            "AML-C1",
            "HIGH",
            "Control Not Defined: Customer onboarding is in scope but PRF does not define a KYC/CDD workflow.",
            "Define and document end-to-end KYC/CDD workflow (capture, verification, approval, exceptions) with auditable logs.",
        )
        add(
            "AML-C2",
            "HIGH",
            "Control Not Defined: PRF does not specify risk-based customer classification (Low/Medium/High) and corresponding due diligence.",
            "Implement risk-based customer profiling with configurable tiers and due diligence requirements; store rationale as audit evidence.",
        )
        add(
            "AML-C3",
            "MEDIUM",
            "Control Not Defined: PRF does not define periodic KYC refresh triggers (time-based or event-driven).",
            "Define periodic and event-driven KYC refresh mechanism including evidence capture and escalation paths.",
        )

    # TRANSACTION RISK RULES
    if payments:
        add(
            "AML-T1",
            "HIGH",
            "Control Not Defined: Payments/transfers appear in scope but PRF does not define transaction monitoring threshold logic.",
            "Define transaction monitoring scenarios/thresholds (amount, velocity, typologies) and case management workflow.",
        )
        add(
            "AML-T2",
            "HIGH",
            "Control Not Defined: PRF does not define structuring detection (multiple small transactions) controls.",
            "Implement velocity/structuring detection rules with alerting, investigation, and auditable outcomes.",
        )
        if cross_border:
            add(
                "AML-T3",
                "CRITICAL",
                "Control Not Defined: Cross-border payments appear in scope but PRF does not define geo-risk scoring or country risk controls.",
                "Implement geo-risk scoring and country risk controls for cross-border payments with documented governance approvals.",
            )

    # SANCTIONS SCREENING RULES
    if onboarding or payments:
        add(
            "AML-S1",
            "CRITICAL",
            "Control Not Defined: PRF does not define real-time sanctions screening for onboarding and/or payments (customer/beneficiary/related parties).",
            "Integrate real-time sanctions screening with deterministic match thresholds, case workflow, and escalation before go-live.",
        )
        add(
            "AML-S2",
            "HIGH",
            "Control Not Defined: PRF does not define near real-time sanctions list update mechanism and operational controls.",
            "Implement near real-time list updates, versioning, and evidence of update operations and testing.",
        )
        add(
            "AML-S3",
            "HIGH",
            "Control Not Defined: PRF does not define beneficiary screening.",
            "Define beneficiary screening scope and matching logic; ensure logs are auditable and tied to payment events.",
        )

    # PEP RULES
    if onboarding:
        add(
            "AML-P1",
            "HIGH",
            "Control Not Defined: PRF does not define PEP identification mechanism during onboarding and ongoing screening.",
            "Implement PEP screening at onboarding and periodic refresh with approvals and evidence capture.",
        )
        add(
            "AML-P2",
            "CRITICAL",
            "Control Not Defined: PRF does not define enhanced monitoring logic for identified PEP customers.",
            "Define enhanced due diligence and enhanced monitoring scenarios for PEPs with governance approvals and audit trails.",
        )

    # REPORTING RULES
    if prf.aml_relevance or onboarding or payments:
        add(
            "AML-R1",
            "CRITICAL",
            "Control Not Defined: PRF does not define STR/SAR trigger logic, investigation workflow, ownership, and filing obligations.",
            "Define STR trigger conditions, investigation workflow, ownership, and filing timelines; ensure evidence retention.",
        )
        add(
            "AML-R2",
            "HIGH",
            "Control Not Defined: PRF does not define STR/SAR filing SLA and confirmation it meets regulatory timelines.",
            "Define STR/SAR filing SLAs aligned to regulatory timelines and ensure evidence of filing and acknowledgements is retained.",
        )
        add(
            "AML-R3",
            "HIGH",
            "Control Not Defined: PRF does not confirm AML alerts are logged, immutable, and auditable end-to-end.",
            "Implement tamper-evident audit logging for alerts, decisions, overrides, and escalations with retention controls.",
        )

    # GOVERNANCE RULES
    add(
        "AML-G1",
        "MEDIUM",
        "Control Not Defined: PRF does not map the design to a specific AML policy version and control catalog.",
        "Map project controls to the current AML policy/control catalog version and retain mapping as audit evidence.",
    )
    add(
        "AML-G2",
        "HIGH",
        "Control Not Defined: PRF does not define escalation workflow to AML Compliance Officer for AML/sanctions/PEP alerts and overrides.",
        "Implement formal escalation workflow with segregation of duties, approval SLAs, and auditable outcomes.",
    )

    if prf.genai_component and (prf.aml_relevance or _keyword_present(aml_policy_excerpt or "", ["aml", "sanctions", "screening"])):
        add(
            "AML-G3",
            "CRITICAL",
            "Control Not Defined: GenAI/model-based AML-related decisioning indicated but no model validation, documentation, or monitoring controls are defined.",
            "Perform model validation and documentation (purpose, limitations, bias, monitoring, change control) prior to approval.",
        )

    sum_rule_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity.lower() == "critical")

    risk_score = _normalize_score(sum_rule_scores)
    if critical_count > 1 and risk_score < 80:
        risk_score = 80

    risk_level = _risk_level(risk_score)

    retrieval_scores = [h.relevance_score for h in evidence]
    has_evidence = ref is not None
    confidence = compute_confidence(ConfidenceInputs(retrieval_scores=retrieval_scores, has_evidence=has_evidence))

    explainability = (
        "Deterministic rule evaluation applied at design stage. "
        "Where PRF does not define required AML controls, findings are marked 'Control Not Defined'."
    )

    out = {
        "domain": "AML",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "regulatory_reference": f.regulatory_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": explainability,
    }

    log_agent_decision(
        agent_name="AML Risk Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=risk_score,
        confidence_0_1=confidence,
        domain=RiskDomain.aml.value,
    )

    return out


def assess_aml_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_aml(prf=prf, evidence=evidence)

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        evs: List[EvidenceClause] = []
        if f.get("regulatory_reference"):
            evs.append(
                EvidenceClause(
                    source=str(f.get("regulatory_reference")),
                    excerpt="",
                    relevance_score=None,
                )
            )
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
        domain=RiskDomain.aml,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )

