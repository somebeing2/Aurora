from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class IEEEFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    ieee_reference: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 25, max = 750
    max_total = 750
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


def assess_ieee_governance(
    *,
    prf: ProjectRequestForm,
    architecture_overview: Optional[str],
    evidence: Sequence[RetrievalHit],
    sdlc_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic IEEE software engineering standards compliance review (planning stage)."""

    ref = _evidence_source(evidence)

    findings: List[IEEEEFinding] = []

    def add(rule_id: str, severity: str, issue: str, ieee_ref: str, rec: str) -> None:
        findings.append(
            IEEEFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                ieee_reference=ieee_ref,
                recommendation=rec,
            )
        )

    # REQUIREMENTS ENGINEERING (IEEE 29148)
    add("IEEE-R1", "HIGH", "Not Defined: SRS not planned/identified", "IEEE 29148", "Plan and produce SRS prior to build")
    add("IEEE-R2", "HIGH", "Not Defined: Requirements traceability matrix", "IEEE 29148", "Define RTM covering requirements→design→test")
    add("IEEE-R3", "MEDIUM", "Not Defined: Stakeholder validation process", "IEEE 29148", "Define stakeholder validation and sign-off")
    add("IEEE-R4", "HIGH", "Not Defined: Non-functional requirements", "IEEE 29148", "Document NFRs (security, performance, availability)")

    # SOFTWARE LIFE CYCLE (IEEE 12207)
    add("IEEE-L1", "MEDIUM", "Not Defined: SDLC model (Agile/Waterfall/Hybrid)", "IEEE 12207", "Define SDLC model and governance")
    add("IEEE-L2", "HIGH", "Not Defined: Lifecycle phase gates", "IEEE 12207", "Define phase gates and entry/exit criteria")
    add("IEEE-L3", "MEDIUM", "Not Defined: Maintenance strategy", "IEEE 12207", "Define maintenance/support model and SLAs")
    add("IEEE-L4", "HIGH", "Not Defined: Transition-to-operations plan", "IEEE 12207", "Define go-live readiness + handover plan")

    # VERIFICATION & VALIDATION (IEEE 1012)
    add("IEEE-V1", "HIGH", "Not Defined: Independent verification", "IEEE 1012", "Define IV&V independence criteria and scope")
    add("IEEE-V2", "HIGH", "Not Defined: Validation criteria", "IEEE 1012", "Define validation criteria and acceptance conditions")
    add("IEEE-V3", "HIGH", "Not Defined: Acceptance testing plan", "IEEE 1012", "Define UAT/acceptance testing plan")
    add("IEEE-V4", "MEDIUM", "Not Defined: Regression testing strategy", "IEEE 1012", "Define regression suite and automation targets")

    # QUALITY ASSURANCE (IEEE 730)
    add("IEEE-Q1", "CRITICAL", "Not Defined: SQAP (Software Quality Assurance Plan)", "IEEE 730", "Create SQAP before SDLC approval")
    add("IEEE-Q2", "HIGH", "Not Defined: Quality metrics", "IEEE 730", "Define metrics (defect density, coverage, escape rate)")
    add("IEEE-Q3", "HIGH", "Not Defined: Defect tracking", "IEEE 730", "Define defect tracking tool/workflow and triage")
    add("IEEE-Q4", "MEDIUM", "Not Defined: Audit schedule", "IEEE 730", "Define internal audit cadence and evidence outputs")

    # REVIEWS & AUDITS (IEEE 1028)
    add("IEEE-A1", "HIGH", "Not Defined: Design review", "IEEE 1028", "Plan architecture/design reviews and sign-offs")
    add("IEEE-A2", "HIGH", "Not Defined: Code review process", "IEEE 1028", "Define code review policy (mandatory approvals)")
    add("IEEE-A3", "MEDIUM", "Not Defined: Technical review milestones", "IEEE 1028", "Define formal technical review milestones")

    # RISK MANAGEMENT (IEEE 1540)
    add("IEEE-RM1", "HIGH", "Not Defined: Project risk register", "IEEE 1540", "Create risk register with owners and dates")
    add("IEEE-RM2", "HIGH", "Not Defined: Risk mitigation strategy", "IEEE 1540", "Define mitigations and residual risk acceptance")
    add("IEEE-RM3", "MEDIUM", "Not Defined: Risk monitoring mechanism", "IEEE 1540", "Define cadence and KRIs for monitoring")

    # CONFIGURATION MANAGEMENT
    add("IEEE-CM1", "HIGH", "Not Defined: Version control system", "IEEE 12207", "Define Git/VC system, branching, access")
    add("IEEE-CM2", "HIGH", "Not Defined: Change approval process", "IEEE 12207", "Define CAB/approvals and segregation of duties")
    add("IEEE-CM3", "MEDIUM", "Not Defined: Release management process", "IEEE 12207", "Define release strategy and rollback")

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 1 and risk_score < 85:
        risk_score = 85

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "IEEE Software Governance",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "ieee_reference": f.ieee_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic IEEE standards review. Missing SDLC artifacts/processes in PRF are flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="IEEE Standards Compliance Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={
            "prf": prf.model_dump(),
            "architecture_overview": architecture_overview,
            "evidence_sources": [h.source for h in evidence],
        },
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain=RiskDomain.governance_sdlc.value,
    )

    return out


def assess_ieee_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_ieee_governance(prf=prf, architecture_overview=prf.additional_context, evidence=evidence)

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        evs: List[EvidenceClause] = []
        src = _evidence_source(evidence)
        if src:
            evs.append(EvidenceClause(source=str(src), excerpt="", relevance_score=None))

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
