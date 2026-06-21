from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class RiskDomain(str, Enum):
    legal = "legal"
    compliance = "compliance"
    dpep = "dpep"
    aml = "aml"
    it_security = "it_security"
    governance_sdlc = "governance_sdlc"


DOMAIN_WEIGHTS: Dict[RiskDomain, float] = {
    RiskDomain.legal: 0.20,
    RiskDomain.compliance: 0.25,
    RiskDomain.dpep: 0.20,
    RiskDomain.aml: 0.20,
    RiskDomain.it_security: 0.15,
}


class EvidenceClause(BaseModel):
    source: str = Field(..., description="Document filename or ID")
    excerpt: str = Field(..., description="Quoted supporting clause")
    relevance_score: Optional[float] = Field(None, description="Retriever relevance if available")


class DomainFinding(BaseModel):
    title: str
    description: str
    risk_level: str = Field(..., description="e.g., Low/Medium/High/Critical")
    remediation: List[str] = Field(default_factory=list)
    evidence: List[EvidenceClause] = Field(default_factory=list)
    explainability: Optional[str] = Field(None, description="Why this is a risk and what controls mitigate it")
    governance_flags: List[str] = Field(default_factory=list, description="E.g., VAGUE_LANGUAGE, NO_EVIDENCE")


class DomainRiskResult(BaseModel):
    domain: RiskDomain
    score_0_100: int = Field(..., ge=0, le=100)
    confidence_0_1: float = Field(..., ge=0.0, le=1.0)
    summary: str
    findings: List[DomainFinding] = Field(default_factory=list)


class EnterpriseRiskReport(BaseModel):
    prf_project_name: str
    generated_at_utc: str

    domain_results: List[DomainRiskResult]

    enterprise_risk_score_0_100: float = Field(..., ge=0.0, le=100.0)
    approval_recommendation: str = Field(..., description="APPROVE / APPROVE_WITH_REMEDIATION / REJECT")
    mandatory_remediation: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)

    control_effectiveness: Optional[float] = Field(
        None,
        description="0-1 control effectiveness used for residual risk computation (if available)",
    )
    residual_risk: Optional[Dict[str, object]] = Field(
        None,
        description="Residual risk computation output (JSON) if executed",
    )
    maturity: Optional[Dict[str, object]] = Field(
        None,
        description="Maturity assessment output (JSON) if executed",
    )
    mcl_control_mapping: Optional[List[Dict[str, object]]] = Field(
        None,
        description="Mapping of findings to Master Control Library controls (JSON)",
    )
    evidence_validation: Optional[List[Dict[str, object]]] = Field(
        None,
        description="Evidence engine validation outputs (JSON)",
    )
    sampling_testing: Optional[Dict[str, object]] = Field(
        None,
        description="Sampling/testing summary output (JSON)",
    )
    enterprise_meta_governance: Optional[Dict[str, object]] = Field(
        None,
        description="Enterprise meta governance aggregation output (JSON)",
    )

    execution_state: Optional[Dict[str, object]] = Field(
        None,
        description="Orchestrator execution state (agent status, errors, retries) if captured",
    )

    audit_trail_id: Optional[str] = None


@dataclass(frozen=True)
class AggregationInputs:
    domain_scores: Dict[RiskDomain, int]


def compute_enterprise_risk_score(inputs: AggregationInputs) -> float:
    """Deterministic enterprise risk scoring.

    Enterprise_Risk = Σ(Domain_Risk × Weight_Factor)

    Notes:
    - Only domains in DOMAIN_WEIGHTS contribute to the score.
    - Governance/SDLC risk is reported but not included in the weighted formula unless you extend DOMAIN_WEIGHTS.
    """

    total = 0.0
    for domain, weight in DOMAIN_WEIGHTS.items():
        score = float(inputs.domain_scores.get(domain, 0))
        total += score * weight
    return round(total, 2)


def recommendation_from_score(score_0_100: float) -> str:
    if score_0_100 >= 80:
        return "REJECT"
    if score_0_100 >= 55:
        return "APPROVE_WITH_REMEDIATION"
    return "APPROVE"


def new_report_skeleton(project_name: str, domain_results: List[DomainRiskResult]) -> EnterpriseRiskReport:
    domain_scores: Dict[RiskDomain, int] = {r.domain: r.score_0_100 for r in domain_results}
    score = compute_enterprise_risk_score(AggregationInputs(domain_scores=domain_scores))
    rec = recommendation_from_score(score)

    mandatory: List[str] = []
    evidence_refs: List[str] = []
    for dr in domain_results:
        for f in dr.findings:
            mandatory.extend([x for x in f.remediation if x])
            for e in f.evidence:
                if e.source:
                    evidence_refs.append(e.source)

    return EnterpriseRiskReport(
        prf_project_name=project_name,
        generated_at_utc=datetime.utcnow().isoformat() + "Z",
        domain_results=domain_results,
        enterprise_risk_score_0_100=score,
        approval_recommendation=rec,
        mandatory_remediation=sorted(set(mandatory)),
        evidence_references=sorted(set(evidence_refs)),
    )
