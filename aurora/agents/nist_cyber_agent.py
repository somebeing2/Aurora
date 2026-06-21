from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class NISTFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    nist_reference: str
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


def assess_nist_csf(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    security_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic NIST CSF review at design stage."""

    ref = _evidence_source(evidence)

    findings: List[NISTFinding] = []

    def add(rule_id: str, severity: str, issue: str, nist_ref: str, rec: str) -> None:
        findings.append(
            NISTFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                nist_reference=nist_ref,
                recommendation=rec,
            )
        )

    add(
        "NIST-I1",
        "HIGH",
        "Not Defined: Asset inventory is not defined for the system (applications, data stores, integrations, identities).",
        "NIST CSF Identify",
        "Define asset inventory and ownership, including data flow/integration inventory.",
    )
    add(
        "NIST-P1",
        "HIGH",
        "Not Defined: Access control policy is not defined.",
        "NIST CSF Protect",
        "Define access control policy, IAM model, least privilege, and privileged access governance.",
    )
    add(
        "NIST-D1",
        "HIGH",
        "Not Defined: Continuous monitoring is not defined.",
        "NIST CSF Detect",
        "Define continuous monitoring, logging, detection rules, and SIEM integration.",
    )
    add(
        "NIST-R1",
        "CRITICAL",
        "Not Defined: Incident response plan is not defined.",
        "NIST CSF Respond",
        "Define incident response plan, runbooks, escalation, and reporting obligations.",
    )
    add(
        "NIST-RE1",
        "HIGH",
        "Not Defined: Recovery testing is not defined.",
        "NIST CSF Recover",
        "Define DR/BC recovery testing frequency, scenarios, success criteria, and remediation tracking.",
    )

    sum_scores = sum(f.score for f in findings)
    risk_score = _normalize(sum_scores)

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "NIST CSF Cybersecurity",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "nist_reference": f.nist_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic NIST CSF review. Missing core function controls are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="NIST CSF Compliance Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="nist_csf",
    )

    return out


def assess_nist_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_nist_csf(prf=prf, evidence=evidence)

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
        domain=RiskDomain.it_security,
        score_0_100=int(payload.get("risk_score", 0)),
        confidence_0_1=float(payload.get("confidence_score", 0.0)),
        summary=str(payload.get("explainability_summary", "")),
        findings=df_findings,
    )
