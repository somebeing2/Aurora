from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainFinding, DomainRiskResult, EvidenceClause, RiskDomain
from aurora.rag.retriever import RetrievalHit


@dataclass(frozen=True)
class OWASPFinding:
    rule_id: str
    severity: str
    score: int
    issue: str
    owasp_reference: str
    recommendation: str


_SCORES = {"LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}


def _kw(text: str, words: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def _ctx(prf: ProjectRequestForm, architecture_description: Optional[str]) -> str:
    return f"{prf.customer_impact or ''} {prf.additional_context or ''} {architecture_description or ''}"


def _infer(prf: ProjectRequestForm, architecture_description: Optional[str]):
    c = _ctx(prf, architecture_description)
    return {
        "web": _kw(c, ["web", "portal", "browser", "frontend", "ui"]),
        "mobile": _kw(c, ["mobile", "android", "ios", "app"]),
        "api": _kw(c, ["api", "apis", "microservice", "integration", "gateway"]),
        "micro": _kw(c, ["microservice", "microservices", "service mesh"]),
        "ai": bool(prf.genai_component),
    }


def _evidence_source(evidence: Sequence[RetrievalHit]) -> Optional[str]:
    for h in evidence:
        if h.source:
            return h.source
    return None


def _normalize(sum_scores: int) -> int:
    # Total rules: 38, max = 1140
    max_total = 1140
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


def assess_owasp_security(
    *,
    prf: ProjectRequestForm,
    architecture_description: Optional[str],
    evidence: Sequence[RetrievalHit],
    security_policy_excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    scope = _infer(prf, architecture_description)
    ref = _evidence_source(evidence)

    findings: List[OWASPFinding] = []

    def add(rule_id: str, severity: str, issue: str, ref_name: str, rec: str) -> None:
        findings.append(
            OWASPFinding(
                rule_id=rule_id,
                severity=severity,
                score=_SCORES[severity],
                issue=issue,
                owasp_reference=ref_name,
                recommendation=rec,
            )
        )

    # WEB (7)
    if scope["web"]:
        add("OW-W1", "CRITICAL", "Not Defined: Authn not specified", "OWASP Top 10 – Web Applications", "Define OIDC/SAML, MFA, secure session")
        add("OW-W2", "HIGH", "Not Defined: Input validation", "OWASP Top 10 – Web Applications", "Server-side validation + allowlists")
        add("OW-W3", "HIGH", "Not Defined: Output encoding", "OWASP Top 10 – Web Applications", "Contextual encoding + templating")
        add("OW-W4", "HIGH", "Not Defined: CSRF controls", "OWASP Top 10 – Web Applications", "CSRF tokens + same-site cookies")
        add("OW-W5", "MEDIUM", "Not Defined: Session timeout", "OWASP Top 10 – Web Applications", "Define idle & absolute timeout")
        add("OW-W6", "HIGH", "Not Defined: Login rate limiting", "OWASP Top 10 – Web Applications", "Throttle + lockout + bot defenses")
        add("OW-W7", "MEDIUM", "Not Defined: Secure headers", "OWASP Top 10 – Web Applications", "HSTS, CSP, XFO, XCTO")

    # API (6)
    if scope["api"]:
        add("OW-API1", "CRITICAL", "Not Defined: API authn", "OWASP API Security Top 10", "JWT/OAuth2 with validation")
        add("OW-API2", "CRITICAL", "Not Defined: API authz model", "OWASP API Security Top 10", "RBAC/ABAC, object-level authz")
        add("OW-API3", "HIGH", "Not Defined: API rate limiting", "OWASP API Security Top 10", "Throttle + quotas per client")
        add("OW-API4", "HIGH", "Not Defined: Schema validation", "OWASP API Security Top 10", "OpenAPI schema validation")
        add("OW-API5", "CRITICAL", "Not Defined: Response data minimization", "OWASP API Security Top 10", "Mask sensitive fields, least data")
        add("OW-API6", "HIGH", "Not Defined: API logging", "OWASP API Security Top 10", "Audit logs with correlation IDs")

    # GATEWAY (5)
    if scope["micro"]:
        add("OW-G1", "HIGH", "Not Defined: API gateway", "Secure Coding Best Practices", "Use gateway for north-south traffic")
        add("OW-G2", "HIGH", "Not Defined: Central authn at gateway", "OWASP API Security Top 10", "Centralize authn/authz")
        add("OW-G3", "HIGH", "Not Defined: WAF integration", "OWASP Top 10 – Web Applications", "WAF rules + tuning")
        add("OW-G4", "HIGH", "Not Defined: DDoS protection", "Secure Coding Best Practices", "DDoS controls at edge")
        add("OW-G5", "HIGH", "Not Defined: Throttling/quota", "OWASP API Security Top 10", "Quota enforcement")

    # MOBILE (6)
    if scope["mobile"]:
        add("OW-M1", "CRITICAL", "Not Defined: Local encryption", "OWASP Mobile Top 10", "Encrypt at rest using platform crypto")
        add("OW-M2", "HIGH", "Not Defined: Cert pinning", "OWASP Mobile Top 10", "Implement pinning + rotation")
        add("OW-M3", "MEDIUM", "Not Defined: Root/jailbreak detection", "OWASP Mobile Top 10", "Detect rooted/jailbroken devices")
        add("OW-M4", "HIGH", "Not Defined: Secure key storage", "OWASP Mobile Top 10", "Keystore/Keychain")
        add("OW-M5", "CRITICAL", "Not Defined: No hardcoded secrets", "OWASP Mobile Top 10", "No secrets in app; use vault")
        add("OW-M6", "HIGH", "Not Defined: Secure updates", "OWASP Mobile Top 10", "Signed updates + integrity checks")

    # AI/LLM (7)
    if scope["ai"]:
        add("OW-AI1", "HIGH", "Not Defined: Prompt injection controls", "OWASP LLM Top 10", "Prompt hardening + sandboxing")
        add("OW-AI2", "HIGH", "Not Defined: Prompt input filtering", "OWASP LLM Top 10", "Filter/validate user prompts")
        add("OW-AI3", "CRITICAL", "Not Defined: Tool access restrictions", "OWASP LLM Top 10", "Allowlist tools + scoped permissions")
        add("OW-AI4", "HIGH", "Not Defined: Output filtering/PII masking", "OWASP LLM Top 10", "Mask PII + safety filters")
        add("OW-AI5", "HIGH", "Not Defined: Role-based tool invocation", "OWASP LLM Top 10", "RBAC for tool calls")
        add("OW-AI6", "CRITICAL", "Not Defined: Model access control", "OWASP LLM Top 10", "Authn, network controls, secrets")
        add("OW-AI7", "HIGH", "Not Defined: LLM interaction logging", "OWASP LLM Top 10", "Log prompts/outputs with redaction")

    # DATA (4)
    add("OW-D1", "CRITICAL", "Not Defined: Encryption at rest", "Secure Coding Best Practices", "Encrypt storage + DB, backups")
    add("OW-D2", "CRITICAL", "Not Defined: TLS 1.2+", "Secure Coding Best Practices", "Enforce TLS 1.2+ and strong ciphers")
    add("OW-D3", "HIGH", "Not Defined: Key management", "Secure Coding Best Practices", "KMS/HSM, rotation, access control")
    add("OW-D4", "MEDIUM", "Not Defined: Data classification", "Secure Coding Best Practices", "Reference enterprise data classification")

    # LOGGING (3)
    add("OW-L1", "HIGH", "Not Defined: Centralized logging", "Secure Coding Best Practices", "Centralize logs (SIEM-ready)")
    add("OW-L2", "HIGH", "Not Defined: Alerting", "Secure Coding Best Practices", "Define detections + alert routing")
    add("OW-L3", "HIGH", "Not Defined: Sensitive data masking", "OWASP Top 10 – Web Applications", "Mask secrets/PII in logs")

    sum_scores = sum(f.score for f in findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    risk_score = _normalize(sum_scores)
    if critical_count > 2 and risk_score < 90:
        risk_score = 90

    confidence = compute_confidence(
        ConfidenceInputs(retrieval_scores=[h.relevance_score for h in evidence], has_evidence=(ref is not None))
    )

    out = {
        "domain": "OWASP Application Security",
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.title(),
                "score": f.score,
                "issue": f"Not Defined: {f.issue}" if not f.issue.lower().startswith("not defined") else f.issue,
                "owasp_reference": f.owasp_reference,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "confidence_score": confidence,
        "explainability_summary": "Deterministic OWASP design review. Controls absent in PRF/architecture are marked Not Defined.",
    }

    log_agent_decision(
        agent_name="OWASP Security Review Agent (Deterministic)",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "architecture": architecture_description, "evidence_sources": [h.source for h in evidence]},
        output_payload=out,
        risk_score_0_100=int(out["risk_score"]),
        confidence_0_1=float(out["confidence_score"]),
        domain="owasp_security",
    )

    return out


def assess_owasp_domain_result(*, prf: ProjectRequestForm, evidence: Sequence[RetrievalHit]) -> DomainRiskResult:
    payload = assess_owasp_security(prf=prf, architecture_description=prf.additional_context, evidence=evidence)

    df_findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        df_findings.append(
            DomainFinding(
                title=str(f.get("rule_id")),
                description=str(f.get("issue")),
                risk_level=str(f.get("severity")),
                remediation=[str(f.get("recommendation"))],
                evidence=[
                    EvidenceClause(
                        source=str(_evidence_source(evidence) or ""),
                        excerpt="",
                        relevance_score=None,
                    )
                ]
                if _evidence_source(evidence)
                else [],
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
