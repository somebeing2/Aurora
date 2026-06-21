from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class ITSecurityFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    security_reference: Optional[str]
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


def _infer_internet_facing(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["internet", "public", "external", "customer app", "mobile app", "web app", "api gateway"]) 


def _infer_payments_or_transactions(prf: ProjectRequestForm) -> bool:
    return _keyword_present(
        prf.customer_impact,
        ["payment", "payments", "transfer", "transfers", "upi", "imps", "neft", "rtgs", "transaction", "card"],
    )


def _infer_privileged_access(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["admin", "administrator", "privileged", "root", "sudo", "superuser", "ops console"]) 


def _infer_api_in_scope(prf: ProjectRequestForm) -> bool:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["api", "apis", "microservice", "service", "webhook", "integration"]) 


def _infer_genai_in_scope(prf: ProjectRequestForm) -> bool:
    if prf.genai_component:
        return True
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}"
    return _keyword_present(ctx, ["llm", "genai", "prompt", "rag", "embedding", "model", "chatbot"]) 


def _evidence_reference(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize_score(sum_rule_scores: int) -> int:
    max_total = 600  # 20 rules * 30
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


def assess_it_security_risk(
    *,
    prf: ProjectRequestForm,
    evidence: Sequence[RetrievalHit],
    infosec_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    internet_facing = _infer_internet_facing(prf)
    payments = _infer_payments_or_transactions(prf)
    privileged = _infer_privileged_access(prf)
    api_in_scope = _infer_api_in_scope(prf)
    genai = _infer_genai_in_scope(prf)

    ref = _evidence_reference(evidence)

    findings: List[ITSecurityFinding] = []

    def add(rule_id: str, severity: str, issue: str, recommendation: str) -> None:
        findings.append(
            ITSecurityFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity.upper()],
                issue=issue,
                security_reference=ref,
                recommendation=recommendation,
            )
        )

    add(
        "INFOSEC-G1",
        "HIGH",
        "Not Defined: PRF does not document an Information Security risk assessment (threats, controls, residual risk) and sign-offs.",
        "Perform an InfoSec risk assessment (threat model, control mapping, residual risk) and obtain approvals before build/go-live.",
    )

    if not prf.sdlc_controls_in_place:
        add(
            "INFOSEC-G2",
            "HIGH",
            "Not Defined: PRF does not confirm mandatory SDLC controls (code review, CI/CD approvals, change management) are in place.",
            "Enable SDLC controls: peer review, protected branches, CI checks, artifact signing, approvals, and change management evidence.",
        )

    if prf.hosting_model.value in {"cloud", "hybrid"} and not prf.cloud_provider:
        add(
            "INFOSEC-A1",
            "MEDIUM",
            "Not Defined: Cloud hosting is indicated but PRF does not specify the cloud provider and landing zone controls.",
            "Specify cloud provider, account structure, network segmentation, IAM boundaries, and baseline hardening controls.",
        )

    if prf.customer_data_involved and prf.data_classification.value in {"confidential", "restricted"}:
        add(
            "INFOSEC-D1",
            "CRITICAL",
            "Not Defined: Sensitive customer data is in scope but PRF does not define data flow maps, storage locations, and protection controls.",
            "Document data flows, storage/processing locations, and enforce encryption, access controls, and monitoring for sensitive data.",
        )

    if prf.customer_data_involved:
        add(
            "INFOSEC-D2",
            "HIGH",
            "Not Defined: PRF does not define data retention, secure deletion, and backup protection requirements.",
            "Define retention schedules, backup encryption, secure deletion, and restoration testing; retain evidence.",
        )

    add(
        "INFOSEC-IAM1",
        "CRITICAL",
        "Not Defined: PRF does not define authentication and MFA requirements for users/admins and service-to-service access.",
        "Define authentication, MFA, session management, and service identity (OIDC/JWT/mTLS) aligned to enterprise standards.",
    )

    add(
        "INFOSEC-IAM2",
        "HIGH",
        "Not Defined: PRF does not define role-based access control (RBAC) and least-privilege permission boundaries.",
        "Define RBAC roles, least privilege, periodic access review, and separation of duties for privileged actions.",
    )

    if privileged:
        add(
            "INFOSEC-IAM3",
            "CRITICAL",
            "Not Defined: Privileged/admin access appears in scope but PRF does not define PAM controls and break-glass procedures.",
            "Implement PAM, just-in-time access, break-glass with approvals, and full session/audit logging for privileged actions.",
        )

    add(
        "INFOSEC-CRYPTO1",
        "CRITICAL",
        "Not Defined: PRF does not define encryption at rest/in transit and key management (KMS/HSM) requirements.",
        "Define crypto standards (TLS, at-rest encryption), key management (KMS/HSM), key rotation, and secret handling.",
    )

    add(
        "INFOSEC-LOG1",
        "HIGH",
        "Not Defined: PRF does not define centralized logging, SIEM integration, alerting, and retention.",
        "Define log sources, SIEM onboarding, alerting, retention, and access controls; ensure logs exclude secrets and sensitive payloads.",
    )

    if internet_facing:
        add(
            "INFOSEC-NET1",
            "CRITICAL",
            "Not Defined: Internet-facing exposure is indicated but PRF does not define network security controls (WAF, DDoS, segmentation).",
            "Implement WAF, DDoS protection, rate limiting, network segmentation, and secure ingress/egress controls.",
        )

    if api_in_scope:
        add(
            "INFOSEC-API1",
            "HIGH",
            "Not Defined: API/integration is indicated but PRF does not define API security controls (authz, schema validation, throttling).",
            "Define API security: strong authz, input validation, schema enforcement, throttling, and secure webhook verification.",
        )

    add(
        "INFOSEC-VULN1",
        "HIGH",
        "Not Defined: PRF does not define vulnerability management (SAST/DAST/SCA) and remediation SLAs.",
        "Enable SAST/DAST/SCA, define severity-based remediation SLAs, and retain scan reports as evidence.",
    )

    if prf.pen_test_required is True or internet_facing or prf.customer_data_involved:
        add(
            "INFOSEC-VAPT1",
            "CRITICAL",
            "Not Defined: PRF does not define VAPT/penetration testing scope, go-live gating, and exception process.",
            "Define VAPT scope, success criteria, remediation gating for go-live, and formal risk acceptance for exceptions.",
        )

    add(
        "INFOSEC-IR1",
        "CRITICAL",
        "Not Defined: PRF does not define incident response (detection, triage, containment, forensics, reporting) and drills.",
        "Define IR runbooks, on-call/escalations, forensics readiness, reporting timelines, and conduct tabletop exercises.",
    )

    if prf.vendor_involvement:
        add(
            "INFOSEC-TPRM1",
            "CRITICAL",
            "Not Defined: Third-party involvement is indicated but PRF does not document security due diligence and minimum security requirements.",
            "Perform vendor security due diligence, define minimum controls (SOC2/ISO27001 posture, VAPT, patching, logging), and capture approvals.",
        )
        add(
            "INFOSEC-TPRM2",
            "HIGH",
            "Not Defined: PRF does not define vendor access controls, data sharing boundaries, and audit rights.",
            "Define vendor access model (least privilege), data sharing scope, monitoring, and contractual audit/right-to-assess clauses.",
        )

    if payments:
        add(
            "INFOSEC-PAY1",
            "CRITICAL",
            "Not Defined: Payments/transactions appear in scope but PRF does not define fraud controls and transaction monitoring requirements.",
            "Define transaction integrity controls, fraud detection/monitoring, velocity controls, and reconciliation evidence.",
        )

    if genai:
        add(
            "INFOSEC-AI1",
            "HIGH",
            "Not Defined: GenAI/LLM usage appears in scope but PRF does not define prompt/data handling, model access controls, and output safety controls.",
            "Define GenAI controls: prompt/data classification, redaction, model access boundaries, logging, and output safety/validation.",
        )

    add(
        "INFOSEC-BCP1",
        "MEDIUM",
        "Not Defined: PRF does not define availability objectives (RTO/RPO), backup/restore testing, and resilience controls.",
        "Define RTO/RPO, implement backups, test restores, and design resilience (multi-AZ, failover) appropriate to criticality.",
    )

    sum_rule_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
    risk_score = _normalize_score(sum_rule_scores)
    if critical_count > 2 and risk_score < 85:
        risk_score = 85

    risk_level = _risk_level(risk_score)

    retrieval_scores = [h.relevance_score for h in evidence]
    has_evidence = ref is not None
    confidence = compute_confidence(ConfidenceInputs(retrieval_scores=retrieval_scores, has_evidence=has_evidence))

    explainability = (
        "Deterministic Information Security rule evaluation at project design stage. "
        "Where PRF does not define required security controls, findings are marked 'Not Defined'. "
        "Security references are limited to retrieved evidence sources when available."
    )

    out = {
        "domain": "IT Security",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f.issue,
                "security_reference": f.security_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": explainability,
    }

    log_agent_decision(
        agent_name="IT Security Assessment Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=risk_score,
        confidence_0_1=confidence,
        domain=RiskDomain.it_security.value,
    )

    return out


def assess_it_security_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_it_security_risk(prf=prf, evidence=evidence)

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        evs: List[EvidenceClause] = []
        if f.get("security_reference"):
            evs.append(EvidenceClause(source=str(f.get("security_reference")), excerpt="", relevance_score=None))
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
