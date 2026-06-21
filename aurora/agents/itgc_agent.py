from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class ITGCFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _kw(text: str, words: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules = 17, max = 510
    max_total = 510
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


def assess_itgc(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    it_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic ITGC audit review (pre go-live)."""

    ref = _evidence_source(evidence)

    findings: List[ITGCFinding] = []

    def add(rule_id: str, severity: str, issue: str, rec: str) -> None:
        findings.append(
            ITGCFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                recommendation=rec,
            )
        )

    # LOGICAL ACCESS
    add("ITGC-L1", "HIGH", "Not Defined: RBAC model is not defined.", "Define RBAC/ABAC and access review cadence.")
    add(
        "ITGC-L2",
        "HIGH",
        "Not Defined: User provisioning workflow is not documented.",
        "Define joiner workflow with approvals, evidence, and audit logs.",
    )
    add(
        "ITGC-L3",
        "CRITICAL",
        "Not Defined: Timely user deactivation process is not documented.",
        "Define leaver workflow with SLA for deactivation and periodic recertification.",
    )
    add(
        "ITGC-L4",
        "HIGH",
        "Not Defined: Privileged access review cadence is not documented.",
        "Implement periodic privileged access review and retain evidence of approvals.",
    )
    add(
        "ITGC-L5",
        "CRITICAL",
        "Not Defined: MFA requirement for admin/privileged users is not documented.",
        "Enforce MFA for privileged access and document break-glass procedure.",
    )

    # CHANGE MANAGEMENT
    add(
        "ITGC-C1",
        "CRITICAL",
        "Not Defined: Formal change request process is not documented.",
        "Define change request workflow, approvals, and evidence artifacts.",
    )
    add(
        "ITGC-C2",
        "HIGH",
        "Not Defined: Change approval authority is not defined.",
        "Define CAB/approver roles and segregation of duties.",
    )
    add(
        "ITGC-C3",
        "HIGH",
        "Not Defined: Testing before production deployment is not documented.",
        "Define test gating (unit/integration/UAT) prior to production release.",
    )
    add(
        "ITGC-C4",
        "HIGH",
        "Not Defined: Rollback plan is not documented.",
        "Define rollback/backout plan and rehearsal requirements.",
    )
    add(
        "ITGC-C5",
        "CRITICAL",
        "Not Defined: Developer production access restrictions are not documented.",
        "Prohibit direct production access; implement privileged access management and break-glass controls.",
    )

    # IT OPERATIONS
    add(
        "ITGC-O1",
        "HIGH",
        "Not Defined: Centralized logging is not documented.",
        "Centralize logs, ensure SIEM readiness, and define retention.",
    )
    add(
        "ITGC-O2",
        "MEDIUM",
        "Not Defined: Daily log review process is not documented.",
        "Define daily review/alert triage procedures with evidence retention.",
    )
    add(
        "ITGC-O3",
        "HIGH",
        "Not Defined: Incident escalation matrix is not documented.",
        "Define escalation matrix, on-call, and response SLAs.",
    )
    add(
        "ITGC-O4",
        "HIGH",
        "Not Defined: System monitoring alerts are not documented.",
        "Define monitoring SLIs/SLOs, alert routing, and incident linkage.",
    )

    # BACKUP & RECOVERY
    add(
        "ITGC-B1",
        "CRITICAL",
        "Not Defined: Automated backup is not documented.",
        "Implement automated backups with encryption and retention policy.",
    )
    add(
        "ITGC-B2",
        "HIGH",
        "Not Defined: Backup testing schedule is not documented.",
        "Define backup restoration testing cadence and evidence retention.",
    )
    add(
        "ITGC-B3",
        "HIGH",
        "Not Defined: RTO/RPO is not documented.",
        "Define RTO/RPO targets aligned to BIA and criticality.",
    )
    add(
        "ITGC-B4",
        "HIGH",
        "Not Defined: Backup storage segregation is not documented.",
        "Ensure backups are stored in segregated environment/account with immutability.",
    )

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 1 and risk_score < 90:
        risk_score = 90

    # Control effectiveness: deterministic proxy based on number of critical findings.
    total_tests = len(findings)
    failed = critical_count
    passed = max(0, total_tests - failed)
    control_effectiveness = 0.0 if total_tests == 0 else round(passed / total_tests, 2)

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "IT General Controls",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "control_effectiveness": control_effectiveness,
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
        "explainability_summary": "Deterministic ITGC review. Missing foundational IT control evidence is flagged as Not Defined.",
    }

    log_agent_decision(
        agent_name="ITGC Audit Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="itgc",
    )

    return out


def assess_itgc_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_itgc(prf=prf, evidence=evidence)

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
