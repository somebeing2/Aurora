from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class ComplianceFinding:
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
        ["payment", "payments", "transfer", "transfers", "upi", "imps", "neft", "rtgs", "remittance", "p2p"],
    )


def _infer_digital_lending_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(prf.customer_impact, ["loan", "lending", "bnpl", "credit", "emi", "digital lending"])


def _infer_cross_border_transfer_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(prf.customer_impact, ["cross-border", "international", "outside india", "offshore"])


def _evidence_reference(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize_score(sum_rule_scores: int) -> int:
    """Normalize Compliance_Domain_Risk to 0–100.

    17 rules * 30 = 510 maximum.
    """

    max_total = 510
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


def assess_rbi_compliance(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    compliance_policy_snippet: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic RBI compliance review at project design stage."""

    onboarding = _infer_onboarding_in_scope(prf)
    payments = _infer_payments_in_scope(prf)
    lending = _infer_digital_lending_in_scope(prf)
    cross_border = _infer_cross_border_transfer_in_scope(prf)
    ref = _evidence_reference(evidence)

    findings: List[ComplianceFinding] = []

    def add(rule_id: str, severity: str, issue: str, recommendation: str) -> None:
        findings.append(
            ComplianceFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity.upper()],
                issue=issue,
                regulatory_reference=ref,
                recommendation=recommendation,
            )
        )

    # IT GOVERNANCE RULES
    add(
        "RBI-G1",
        "HIGH",
        "Not Defined: PRF does not evidence Board/IT Steering approval and oversight for the initiative.",
        "Define governance approvals (Board/IT Steering), include minutes/approval IDs, and assign accountable owners before approval.",
    )
    add(
        "RBI-G2",
        "HIGH",
        "Not Defined: PRF does not include a documented IT risk assessment aligned to RBI IT governance expectations.",
        "Perform and attach an IT risk assessment (inherent risk, controls, residual risk) and obtain sign-offs.",
    )
    add(
        "RBI-G3",
        "MEDIUM",
        "Not Defined: PRF does not reference formal change management (CAB approvals, SoD, release controls).",
        "Reference change management controls (CAB, SoD, approvals, rollback) and define evidence artifacts.",
    )

    # CYBER SECURITY RULES
    if prf.customer_data_involved:
        add(
            "RBI-C1",
            "HIGH",
            "Not Defined: System handles customer data but PRF does not define a VAPT plan/timeline and go-live gating.",
            "Define VAPT scope, timeline, remediation tracking, and ensure completion prior to go-live.",
        )
    add(
        "RBI-C2",
        "HIGH",
        "Not Defined: PRF does not define log monitoring and SIEM integration requirements.",
        "Define centralized logging, SIEM integration, alerting, and retention aligned to cyber security monitoring requirements.",
    )
    add(
        "RBI-C3",
        "CRITICAL",
        "Not Defined: PRF does not define incident response mechanism (detection, triage, containment, reporting, drills).",
        "Define incident response process, roles, runbooks, and evidence of preparedness including reporting obligations.",
    )

    # DATA LOCALIZATION RULES
    if payments:
        add(
            "RBI-D1",
            "CRITICAL",
            "Not Defined: Payments appear in scope but PRF does not explicitly confirm payment data localization in India and storage/processing locations.",
            "Explicitly document payment data storage/processing in India, including cloud region controls and vendor processing locations.",
        )

    if prf.hosting_model.value in {"cloud", "hybrid"} and not prf.cloud_provider:
        add(
            "RBI-D2",
            "MEDIUM",
            "Not Defined: Cloud hosting is indicated but PRF does not define the cloud provider.",
            "Specify cloud provider, deployment model, and compliance posture including region/data residency controls.",
        )

    if prf.customer_data_involved and (cross_border or prf.vendor_involvement):
        add(
            "RBI-D3",
            "HIGH",
            "Not Defined: Cross-border data transfer and processing assessment is not documented (including vendor processing locations).",
            "Document cross-border transfer assessment, data flow maps, and approvals; implement controls for DPDP and RBI expectations.",
        )

    # OUTSOURCING RULES
    if prf.vendor_involvement:
        add(
            "RBI-O1",
            "CRITICAL",
            "Not Defined: Third-party vendor involvement is indicated but PRF does not document due diligence (security, financial, compliance) and risk acceptance.",
            "Perform vendor due diligence, document risk assessment, define controls, and obtain approvals prior to contracting.",
        )
        add(
            "RBI-O2",
            "HIGH",
            "Not Defined: PRF does not define an outsourcing exit strategy and business continuity transition plan.",
            "Define exit strategy, transition plan, data return/destruction, and continuity controls.",
        )
        add(
            "RBI-O3",
            "HIGH",
            "Not Defined: PRF does not confirm RBI/regulated-entity audit rights in vendor contracts and access to records.",
            "Ensure contracts include audit rights, access to data/records, and regulatory cooperation clauses.",
        )

    # KYC & CUSTOMER PROTECTION RULES
    if onboarding:
        add(
            "RBI-K1",
            "CRITICAL",
            "Not Defined: Customer onboarding appears in scope but PRF does not define a compliant KYC workflow and control evidence.",
            "Define RBI-aligned KYC workflow (CDD, verification, risk classification, periodic refresh) with audit evidence and approvals.",
        )
    add(
        "RBI-K2",
        "HIGH",
        "Not Defined: PRF does not define customer grievance redressal mechanism and SLA ownership.",
        "Define grievance redressal workflow, escalation, SLAs, and auditability aligned to customer protection expectations.",
    )
    if lending:
        add(
            "RBI-K3",
            "CRITICAL",
            "Not Defined: Digital lending appears in scope but PRF does not define transparency disclosures (pricing, APR, fees, grievance, consent).",
            "Implement RBI Digital Lending transparency disclosures and consent capture with audit evidence.",
        )

    # REPORTING & INCIDENT RULES
    add(
        "RBI-R1",
        "CRITICAL",
        "Not Defined: PRF does not define mechanism and ownership for reporting cyber incidents to RBI within required timelines.",
        "Define RBI incident reporting workflow, ownership, timelines, and evidence artifacts.",
    )
    add(
        "RBI-R2",
        "HIGH",
        "Not Defined: PRF does not define breach notification process (customers/regulators) and communication governance.",
        "Define breach notification process, approvals, templates, and evidence retention aligned to regulatory and DPDP expectations.",
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
        "Deterministic RBI compliance rule evaluation at project design stage. "
        "Where PRF does not define required controls, findings are marked 'Not Defined'. "
        "Regulatory references are limited to retrieved evidence sources when available."
    )

    out = {
        "domain": "RBI Compliance",
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
        agent_name="RBI Compliance Review Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=risk_score,
        confidence_0_1=confidence,
        domain=RiskDomain.compliance.value,
    )

    return out


def assess_compliance_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_rbi_compliance(prf=prf, evidence=evidence)

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
        domain=RiskDomain.compliance,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )

