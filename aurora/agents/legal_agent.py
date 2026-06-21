from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class LegalFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    regulatory_reference: Optional[str]
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _keyword_present(text: str, keywords: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(k.lower() in t for k in keywords)


def _infer_onboarding_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(
        prf.customer_impact,
        ["onboarding", "account opening", "kyc", "cdd", "identity verification"],
    )


def _infer_payments_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(
        prf.customer_impact,
        ["payment", "payments", "transfer", "transfers", "upi", "imps", "aeps", "neft", "rtgs", "settlement"],
    )


def _infer_npci_in_scope(prf: ProjectRequestForm) -> bool:
    return _keyword_present(prf.customer_impact, ["upi", "imps", "aeps", "npci"])


def _infer_core_banking_in_scope(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["core banking", "cbs", "payment switch"]) 


def _infer_cross_border(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["cross-border", "international", "outside india", "offshore"]) 


def _evidence_reference(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize_score(sum_rule_scores: int) -> int:
    max_total = 480  # 16 rules * 30
    if sum_rule_scores <= 0:
        return 0
    score = int(round((sum_rule_scores / max_total) * 100))
    return max(0, min(100, score))


def _risk_level(score_0_100: int) -> str:
    if score_0_100 >= 85:
        return "Critical"
    if score_0_100 >= 60:
        return "High"
    if score_0_100 >= 30:
        return "Medium"
    return "Low"


def assess_legal_risk(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    legal_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    payments = _infer_payments_in_scope(prf)
    npci = _infer_npci_in_scope(prf)
    onboarding = _infer_onboarding_in_scope(prf)
    core_banking = _infer_core_banking_in_scope(prf)
    cross_border = _infer_cross_border(prf)
    ref = _evidence_reference(evidence)

    findings: List[LegalFinding] = []

    def add(rule_id: str, severity: str, issue: str, recommendation: str) -> None:
        findings.append(
            LegalFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity.upper()],
                issue=issue,
                regulatory_reference=ref,
                recommendation=recommendation,
            )
        )

    # CONTRACTUAL RISK RULES
    if prf.vendor_involvement:
        add(
            "LEGAL-C1",
            "HIGH",
            "Not Defined: Third-party vendor is involved but PRF does not define contract type (MSA/SOW/DPA).",
            "Define contract type(s) (MSA/SOW/DPA), SLAs, responsibilities, and legal approval workflow prior to contracting.",
        )
        add(
            "LEGAL-C2",
            "HIGH",
            "Not Defined: PRF does not confirm governing law/jurisdiction clause requirements (India).",
            "Include India governing law and jurisdiction clause aligned to bank standards.",
        )
        add(
            "LEGAL-C3",
            "MEDIUM",
            "Not Defined: PRF does not specify indemnity clause requirements.",
            "Define indemnities for data breach, regulatory penalties, IP infringement, and third-party claims.",
        )
        add(
            "LEGAL-C4",
            "HIGH",
            "Not Defined: PRF does not specify limitation of liability (LoL) cap and carve-outs.",
            "Define LoL cap and carve-outs (confidentiality, IP, fraud, regulatory penalties) aligned to risk appetite.",
        )
        add(
            "LEGAL-C5",
            "HIGH",
            "Not Defined: PRF does not clarify IP ownership/licensing for software deliverables.",
            "Clarify IP ownership/licensing, reuse rights, and post-exit maintenance rights; consider escrow if needed.",
        )

    # RBI & REGULATORY LIABILITY RULES
    if core_banking or payments:
        add(
            "LEGAL-R1",
            "CRITICAL",
            "Not Defined: Core banking/payment impact indicated but RBI notification/approval assessment is not documented.",
            "Assess RBI notification/approval obligations and document the decision with sign-offs.",
        )

    has_rbi_mapping = any(_keyword_present(x, ["rbi", "circular", "master direction"]) for x in prf.regulatory_regimes)
    if not has_rbi_mapping:
        add(
            "LEGAL-R2",
            "HIGH",
            "Not Defined: PRF does not map the project to relevant RBI circulars/Master Directions.",
            "Create a compliance mapping to applicable RBI circulars/Master Directions and retain as approval evidence.",
        )
    add(
        "LEGAL-R3",
        "HIGH",
        "Not Defined: PRF does not define regulatory reporting obligations (RBI/NPCI) ownership and timelines.",
        "Define reporting obligations, owners, escalation, and evidence artifacts (incidents, outsourcing notifications, customer complaints).",
    )

    # PAYMENT SYSTEM RISK (NPCI / PSS Act)
    if npci:
        add(
            "LEGAL-P1",
            "CRITICAL",
            "Not Defined: NPCI rail integration indicated but PRF does not document NPCI compliance mapping.",
            "Map requirements to NPCI operating guidelines and define compliance evidence and attestations.",
        )
        add(
            "LEGAL-P2",
            "HIGH",
            "Not Defined: Dispute resolution process for failed/erroneous transactions is not defined.",
            "Define customer dispute process, timelines, chargeback handling (if applicable), and escalation responsibilities.",
        )
        add(
            "LEGAL-P3",
            "HIGH",
            "Not Defined: Settlement and reconciliation responsibility is unclear.",
            "Define settlement, reconciliation, and exception handling responsibilities with RACI and evidence retention.",
        )
        add(
            "LEGAL-P4",
            "CRITICAL",
            "Not Defined: Fraud liability allocation and customer protection responsibilities are not defined.",
            "Define fraud liability allocation, customer reimbursements, and controls aligned to payment system rules and bank policy.",
        )

    # DATA PROTECTION LEGAL RISK
    if prf.customer_data_involved:
        add(
            "LEGAL-D1",
            "CRITICAL",
            "Not Defined: Customer personal data is processed but PRF does not define lawful purpose/consent model.",
            "Define lawful basis/consent model, notices, and purpose limitation aligned to DPDP and banking requirements.",
        )
        if cross_border:
            add(
                "LEGAL-D2",
                "HIGH",
                "Not Defined: Cross-border transfer is indicated but safeguards/approvals are not defined.",
                "Document safeguards, approvals, and contractual controls for cross-border transfers; update data flow maps.",
            )
        add(
            "LEGAL-D3",
            "MEDIUM",
            "Not Defined: PRF does not define data retention period and destruction requirements.",
            "Define retention schedules, legal hold, and secure destruction aligned to regulatory and business requirements.",
        )
        add(
            "LEGAL-D4",
            "HIGH",
            "Not Defined: PRF does not define grievance redressal mechanism for data/privacy issues.",
            "Define grievance redressal workflow, ownership, and response SLAs; retain case records as evidence.",
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
        "Deterministic legal risk evaluation at design stage. "
        "Where PRF does not define required legal/regulatory controls, findings are marked 'Not Defined'. "
        "Regulatory references are limited to retrieved evidence sources when available."
    )

    out = {
        "domain": "Banking Legal Risk",
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
        agent_name="Banking Legal Risk Assessment Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=risk_score,
        confidence_0_1=confidence,
        domain=RiskDomain.legal.value,
    )

    return out


def assess_legal_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_legal_risk(prf=prf, evidence=evidence)

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        evs: List[EvidenceClause] = []
        if f.get("regulatory_reference"):
            evs.append(EvidenceClause(source=str(f.get("regulatory_reference")), excerpt="", relevance_score=None))
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
        domain=RiskDomain.legal,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )
