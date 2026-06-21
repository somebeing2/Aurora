from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class ISOFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    iso_reference: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 11, max = 330
    max_total = 330
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


def assess_iso_governance(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    isms_policy_excerpt: Optional[str] = None,
    bcms_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic ISO/IEC 27001 + ISO 22301 governance review (design stage)."""

    ref = _evidence_source(evidence)

    findings: List[ISOFinding] = []

    def add(rule_id: str, severity: str, issue: str, iso_ref: str, rec: str) -> None:
        findings.append(
            ISOFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                iso_reference=iso_ref,
                recommendation=rec,
            )
        )

    # ISO 27001 (ISMS)
    add(
        "ISO-IS1",
        "HIGH",
        "Not Defined: Information Security Risk Assessment is not documented for the project.",
        "ISO/IEC 27001",
        "Perform and document IS risk assessment and treatment plan prior to approval.",
    )
    add(
        "ISO-IS2",
        "MEDIUM",
        "Not Defined: Statement of Applicability (SoA) reference is not provided.",
        "ISO/IEC 27001",
        "Reference the ISMS Statement of Applicability and map applicable controls to the project.",
    )
    add(
        "ISO-IS3",
        "HIGH",
        "Not Defined: Access control policy and enforcement model are not defined.",
        "ISO/IEC 27001",
        "Define access control policy, IAM model, least privilege, and privileged access governance.",
    )
    add(
        "ISO-IS4",
        "HIGH",
        "Not Defined: Encryption standards (at rest/in transit) are not defined.",
        "ISO/IEC 27001",
        "Define encryption standards, approved algorithms, and key management requirements.",
    )
    add(
        "ISO-IS5",
        "HIGH",
        "Not Defined: Supplier security assessment process is not defined.",
        "ISO/IEC 27001",
        "Define supplier security due diligence, contract requirements, and ongoing monitoring.",
    )
    add(
        "ISO-IS6",
        "CRITICAL",
        "Not Defined: Incident response plan is not defined.",
        "ISO/IEC 27001",
        "Define incident response roles, runbooks, escalation, and evidence retention.",
    )

    # ISO 22301 (BCMS)
    add(
        "ISO-BC1",
        "CRITICAL",
        "Not Defined: Business Impact Analysis (BIA) is not documented.",
        "ISO 22301",
        "Perform BIA to identify critical services, impact tolerances, dependencies, and recovery requirements.",
    )
    add(
        "ISO-BC2",
        "HIGH",
        "Not Defined: Recovery objectives (RTO/RPO) are not defined.",
        "ISO 22301",
        "Define RTO/RPO targets per service, aligned to BIA outcomes and regulatory expectations.",
    )
    add(
        "ISO-BC3",
        "CRITICAL",
        "Not Defined: Disaster Recovery Plan (DRP) is not defined.",
        "ISO 22301",
        "Define DR strategy, DRP runbooks, roles, failover/failback procedures, and evidence artifacts.",
    )
    add(
        "ISO-BC4",
        "HIGH",
        "Not Defined: Backup strategy is not defined.",
        "ISO 22301",
        "Define backup scope, frequency, retention, encryption, restoration testing, and ownership.",
    )
    add(
        "ISO-BC5",
        "MEDIUM",
        "Not Defined: Business continuity testing schedule is not defined.",
        "ISO 22301",
        "Define continuity/DR testing frequency, scenarios, success criteria, and issue remediation tracking.",
    )

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 2 and risk_score < 90:
        risk_score = 90

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "ISO 27001 + ISO 22301",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "iso_reference": f.iso_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic ISO governance review. Missing ISMS/BCMS artifacts are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="ISO Governance Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="iso_governance",
    )

    return out


def assess_iso_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_iso_governance(prf=prf, evidence=evidence)

    df_findings: List[DomainFinding] = []
    src = _evidence_source(evidence)
    evs: List[EvidenceClause] = []
    if src:
        evs.append(EvidenceClause(source=str(src), excerpt="", relevance_score=None))

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
