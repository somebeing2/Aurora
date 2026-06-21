from __future__ import annotations

import json
import os
import random
import re
import traceback
from urllib.parse import urlparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TYPE_CHECKING

from aurora.agents.aml_agent import assess_aml_domain_result
from aurora.agents.compliance_agent import assess_compliance_domain_result
from aurora.agents.data_governance_agent import assess_data_governance
from aurora.agents.enterprise_meta_governance_agent import aggregate_enterprise_governance
from aurora.agents.legal_agent import assess_legal_domain_result
from aurora.agents.maturity_assessment_agent import assess_maturity
from aurora.agents.residual_risk_agent import compute_residual_risk
from aurora.agents.sampling_testing_agent import run_control_sampling, run_sampling_test
from aurora.agents.cobit_governance_agent import assess_cobit_governance
from aurora.agents.ieee_agent import assess_ieee_governance
from aurora.agents.iso_agent import assess_iso_governance
from aurora.agents.itgc_agent import assess_itgc
from aurora.agents.nist_cyber_agent import assess_nist_csf
from aurora.agents.owasp_agent import assess_owasp_security
from aurora.agents.rbi_governance_super_agent import assess_rbi_governance_super
from aurora.governance.audit_logger import log_agent_decision
from aurora.governance.confidence_scoring import ConfidenceInputs, compute_confidence
from aurora.governance.explainability import explain_findings
from aurora.governance.hallucination_detection import governance_flags_for_finding
from aurora.governance.model_risk import genai_governance_checks
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import (
    DomainFinding,
    DomainRiskResult,
    EvidenceClause,
    EnterpriseRiskReport,
    RiskDomain,
    new_report_skeleton,
)
from aurora.rag.retriever import RetrievalHit, build_regulatory_index, retrieve_clauses


if TYPE_CHECKING:
    from langchain_community.llms import Ollama


def _map_findings_to_mcl(domain_results: List[DomainRiskResult]) -> List[Dict[str, object]]:
    """Deterministic, best-effort mapping of findings to MCL controls.

    Since findings are produced by heterogeneous agents, this maps by domain to a small
    set of MCL control IDs.
    """

    domain_to_controls = {
        RiskDomain.aml: ["MCL-AML-001"],
        RiskDomain.it_security: ["MCL-OWASP-001", "MCL-CRYPTO-001", "MCL-ACCESS-001"],
        RiskDomain.compliance: ["MCL-SUPPLIER-001", "MCL-INCIDENT-001", "MCL-ISMS-001"],
        RiskDomain.legal: ["MCL-SUPPLIER-001"],
        RiskDomain.dpep: ["MCL-CRYPTO-001", "MCL-ACCESS-001"],
        RiskDomain.governance_sdlc: ["MCL-IEEE-001", "MCL-ISMS-001"],
    }

    mappings: List[Dict[str, object]] = []
    for dr in domain_results:
        for f in dr.findings:
            mappings.append(
                {
                    "domain": dr.domain.value,
                    "finding_title": f.title,
                    "mcl_control_ids": list(domain_to_controls.get(dr.domain, [])),
                }
            )
    return mappings


def _domain_result_to_agent_output(dr: DomainRiskResult) -> Dict[str, Any]:
    return {
        "domain": dr.domain.value,
        "risk_score": int(dr.score_0_100),
        "risk_level": str(dr.findings[0].risk_level) if dr.findings else "Medium",
        "findings": [
            {
                "rule_id": f.title,
                "severity": str(f.risk_level),
                "score": 30 if str(f.risk_level).lower() == "critical" else 20,
                "issue": f.description,
                "recommendation": (f.remediation[0] if f.remediation else ""),
            }
            for f in dr.findings
        ],
        "confidence_score": float(dr.confidence_0_1),
        "explainability_summary": dr.summary,
    }


def _risk_level_label_from_score(score_0_100: float) -> str:
    if score_0_100 >= 80:
        return "Critical"
    if score_0_100 >= 55:
        return "High"
    if score_0_100 >= 30:
        return "Medium"
    return "Low"


def _map_meta_recommendation_to_report(rec: str) -> str:
    r = (rec or "").strip().lower()
    if r == "reject":
        return "REJECT"
    if r == "conditional":
        return "APPROVE_WITH_REMEDIATION"
    return "APPROVE"


def _merge_domain_results(domain: RiskDomain, results: List[DomainRiskResult]) -> DomainRiskResult:
    if not results:
        return DomainRiskResult(domain=domain, score_0_100=0, confidence_0_1=0.0, summary="", findings=[])

    # Use max score; merge findings; confidence = average
    max_score = max(r.score_0_100 for r in results)
    conf = round(sum(r.confidence_0_1 for r in results) / len(results), 2)
    findings: List[DomainFinding] = []
    for r in results:
        findings.extend(r.findings)

    summary = " ".join([r.summary for r in results if r.summary]).strip()[:2500]
    return DomainRiskResult(
        domain=domain,
        score_0_100=int(max_score),
        confidence_0_1=float(conf),
        summary=summary or explain_findings(findings),
        findings=findings,
    )


def _payload_to_domain_result(*, domain: RiskDomain, payload: Dict[str, Any]) -> DomainRiskResult:
    findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        findings.append(
            DomainFinding(
                title=str(f.get("rule_id", "Finding"))[:160],
                description=str(f.get("issue", ""))[:4000],
                risk_level=str(f.get("severity", "Medium")),
                remediation=[str(f.get("recommendation", ""))[:350]] if str(f.get("recommendation", "")).strip() else [],
                evidence=[],
                explainability=None,
                governance_flags=[],
            )
        )

    score = int(payload.get("risk_score", 0))
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    conf = float(payload.get("confidence_score", 0.0))
    if conf < 0.0:
        conf = 0.0
    if conf > 1.0:
        conf = 1.0

    return DomainRiskResult(
        domain=domain,
        score_0_100=score,
        confidence_0_1=conf,
        summary=str(payload.get("explainability_summary", ""))[:2500],
        findings=findings,
    )


def _scope_flags(prf: ProjectRequestForm) -> Dict[str, bool]:
    ctx = f"{prf.customer_impact or ''} {prf.additional_context or ''}".lower()
    return {
        "customer_data": bool(prf.customer_data_involved),
        "vendor": bool(prf.vendor_involvement),
        "genai": bool(prf.genai_component),
        "aml_relevant": bool(prf.aml_relevance),
        "payments": any(k in ctx for k in ["payment", "payments", "transfer", "upi", "imps", "neft", "rtgs", "settlement"]),
        "onboarding": any(k in ctx for k in ["onboarding", "account opening", "kyc", "cdd", "identity verification"]),
        "cross_border": any(k in ctx for k in ["cross-border", "international", "outside india", "offshore"]),
    }


def _with_retries(
    *,
    exec_state: Dict[str, Any],
    agent_key: str,
    fn,
    max_retries: int = 1,
    on_agent_update: Optional[Callable[[str, Dict[str, Any]], None]] = None,
):
    attempt = 0
    last_err: Optional[str] = None
    while attempt <= max_retries:
        try:
            exec_state["agents"][agent_key] = {"status": "running", "attempt": attempt + 1}
            if on_agent_update is not None:
                on_agent_update(agent_key, exec_state["agents"][agent_key])
            out = fn()

            meta: Dict[str, Any] = {}
            if isinstance(out, DomainRiskResult):
                meta = {
                    "domain": out.domain.value,
                    "score": int(out.score_0_100),
                    "confidence": float(out.confidence_0_1),
                    "findings_count": int(len(out.findings)),
                }
            elif isinstance(out, dict):
                findings = out.get("findings", [])
                meta = {
                    "domain": str(out.get("domain", "")),
                    "score": int(out.get("risk_score", 0) or 0),
                    "confidence": float(out.get("confidence_score", 0.0) or 0.0),
                    "findings_count": int(len(findings)) if isinstance(findings, list) else 0,
                }

            exec_state["agents"][agent_key] = {"status": "completed", "attempt": attempt + 1, "meta": meta}
            if on_agent_update is not None:
                on_agent_update(agent_key, exec_state["agents"][agent_key])
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            exec_state["agents"][agent_key] = {
                "status": "failed",
                "attempt": attempt + 1,
                "error": last_err,
                "trace": traceback.format_exc(limit=6),
            }
            if on_agent_update is not None:
                on_agent_update(agent_key, exec_state["agents"][agent_key])
            attempt += 1
    raise RuntimeError(f"Agent {agent_key} failed after retries: {last_err}")


@dataclass(frozen=True)
class AgentRunContext:
    prf: ProjectRequestForm
    evidence: List[RetrievalHit]


def _ollama_llm() -> "Ollama":
    from langchain_community.llms import Ollama

    raw = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        p = urlparse(raw)
        base_url = f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else raw
    except Exception:
        base_url = raw
    model = os.getenv("OLLAMA_MODEL", "mistral:latest")
    return Ollama(base_url=base_url, model=model, temperature=0.2)


def _extract_json_obj(text: str) -> Dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("Model did not return JSON")
    return json.loads(match.group(0))


def _evidence_to_prompt(evidence: Sequence[RetrievalHit]) -> str:
    if not evidence:
        return "NO_EVIDENCE_RETRIEVED"

    blocks: List[str] = []
    for i, h in enumerate(evidence, start=1):
        score = "" if h.relevance_score is None else f" (score={h.relevance_score:.4f})"
        blocks.append(f"[{i}] SOURCE={h.source}{score}\n{h.excerpt}")

    return "\n\n".join(blocks)


def _domain_agent(
    *,
    name: str,
    domain: RiskDomain,
    domain_instructions: str,
    context: AgentRunContext,
) -> DomainRiskResult:
    from crewai import Agent, Crew, Task

    llm = _ollama_llm()

    evidence_prompt = _evidence_to_prompt(context.evidence)

    system = (
        "You are an enterprise IT governance auditor. "
        "You must produce strictly valid JSON only. "
        "Do not include markdown. Do not include commentary."
    )

    prompt = f"""{system}

PRF (validated JSON):
{context.prf.model_dump_json(indent=2)}

Retrieved evidence clauses:
{evidence_prompt}

Task:
{domain_instructions}

Output JSON schema:
{{
  "score_0_100": 0,
  "summary": "...",
  "findings": [
    {{
      "title": "...",
      "description": "...",
      "risk_level": "Low|Medium|High|Critical",
      "remediation": ["..."],
      "evidence": [{{"source": "...", "excerpt": "..."}}]
    }}
  ]
}}

Rules:
- Ensure every finding includes at least 1 evidence clause excerpt when evidence is available.
- If inputs are insufficient, create a finding and state what information is missing.
- Score must be an integer 0..100.
"""

    agent = Agent(
        role=f"{name}",
        goal=f"Assess {domain.value} risk for PRF using evidence and enterprise governance standards",
        backstory="Banking IT governance and CISA-aligned audit reviewer.",
        llm=llm,
        allow_delegation=False,
        verbose=False,
    )

    task = Task(description=prompt, expected_output="Strict JSON object", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], verbose=False)

    raw = crew.kickoff()
    payload = _extract_json_obj(str(raw))

    findings: List[DomainFinding] = []
    for f in payload.get("findings", []) or []:
        ev_list: List[EvidenceClause] = []
        for ev in f.get("evidence", []) or []:
            ev_list.append(
                EvidenceClause(
                    source=str(ev.get("source", "")) or "unknown",
                    excerpt=str(ev.get("excerpt", ""))[:1800],
                    relevance_score=None,
                )
            )

        finding = DomainFinding(
            title=str(f.get("title", "Finding"))[:160],
            description=str(f.get("description", ""))[:4000],
            risk_level=str(f.get("risk_level", "Medium")),
            remediation=[str(x)[:350] for x in (f.get("remediation", []) or []) if str(x).strip()],
            evidence=ev_list,
        )
        finding.governance_flags.extend(governance_flags_for_finding(finding))
        finding.explainability = finding.explainability or ""
        findings.append(finding)

    has_evidence = any(len(f.evidence) > 0 for f in findings)
    retrieval_scores = [h.relevance_score for h in context.evidence]
    confidence = compute_confidence(ConfidenceInputs(retrieval_scores=retrieval_scores, has_evidence=has_evidence))

    score = int(payload.get("score_0_100", 0))
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    result = DomainRiskResult(
        domain=domain,
        score_0_100=score,
        confidence_0_1=confidence,
        summary=str(payload.get("summary", ""))[:2500],
        findings=findings,
    )

    result.summary = (result.summary or "").strip() or explain_findings(result.findings)

    log_agent_decision(
        agent_name=name,
        prf_project_name=context.prf.project_name,
        input_payload=context.prf.model_dump(),
        output_payload=result.model_dump(),
        risk_score_0_100=result.score_0_100,
        confidence_0_1=result.confidence_0_1,
        domain=domain.value,
    )

    return result


def _agent_query(domain: RiskDomain, prf: ProjectRequestForm) -> str:
    base = f"Project={prf.project_name}. Hosting={prf.hosting_model}. Data={prf.data_classification}. CustomerData={prf.customer_data_involved}. Vendor={prf.vendor_involvement}. RegulatoryImpact={prf.regulatory_impact}. AML={prf.aml_relevance}."

    if domain == RiskDomain.legal:
        return base + " Focus on contracts, IP, liability, third-party, jurisdiction, data processing agreements."
    if domain == RiskDomain.compliance:
        return base + " Focus on regulatory compliance obligations, auditability, record retention, controls, reporting."
    if domain == RiskDomain.dpep:
        return base + " Focus on privacy, PII handling, consent, data minimization, retention, cross-border transfer."
    if domain == RiskDomain.aml:
        return base + " Focus on AML/KYC, transaction monitoring controls, screening, suspicious activity reporting impacts."
    if domain == RiskDomain.it_security:
        return base + " Focus on security controls, encryption, IAM, vulnerability management, pen testing, SDLC security."
    return base + " Focus on SDLC governance, change management, approvals, segregation of duties, evidence generation."


def run_full_audit(
    prf: ProjectRequestForm,
    data_root: Optional[Path] = None,
    *,
    execution_mode: str = "dry_run",
    population_map: Optional[Dict[str, int]] = None,
    selected_agents: Optional[Sequence[str]] = None,
    on_agent_update: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> EnterpriseRiskReport:
    prf = ProjectRequestForm.model_validate(prf.model_dump())
    exec_state: Dict[str, Any] = {
        "scope": _scope_flags(prf),
        "agents": {},
    }

    selected_set = None if selected_agents is None else {str(x).strip().upper() for x in selected_agents if str(x).strip()}

    def is_selected(agent_key: str) -> bool:
        if selected_set is None:
            return True
        return str(agent_key).strip().upper() in selected_set

    def mark_skipped(agent_key: str, reason: str, *, domain: Optional[str] = None) -> None:
        exec_state["agents"][agent_key] = {
            "status": "skipped",
            "attempt": 0,
            "error": None,
            "meta": {
                "domain": domain,
                "reason": reason,
            },
        }
        if on_agent_update is not None:
            on_agent_update(agent_key, exec_state["agents"][agent_key])

    root = data_root or Path("aurora/data")

    build_regulatory_index(root)

    # Phase 2: Deterministic domain agents in recommended order (inherent risk only)
    domain_results_by_domain: Dict[RiskDomain, List[DomainRiskResult]] = {
        RiskDomain.aml: [],
        RiskDomain.compliance: [],
        RiskDomain.legal: [],
        RiskDomain.it_security: [],
        RiskDomain.governance_sdlc: [],
        RiskDomain.dpep: [],
    }

    phase2_agent_outputs: Dict[str, Dict[str, Any]] = {}

    # Helper to fetch evidence once per domain key
    evidence_cache: Dict[str, List[RetrievalHit]] = {}

    def evidence_for(key: str, query: str) -> List[RetrievalHit]:
        if key in evidence_cache:
            return evidence_cache[key]
        ev = retrieve_clauses(query, k=3)
        evidence_cache[key] = ev
        return ev

    # AML
    if is_selected("AML"):
        aml_in_scope = bool(
            exec_state["scope"].get("aml_relevant")
            or exec_state["scope"].get("payments")
            or exec_state["scope"].get("onboarding")
        )
        if aml_in_scope:
            ev = evidence_for("aml", _agent_query(RiskDomain.aml, prf))
            domain_results_by_domain[RiskDomain.aml].append(
                _with_retries(
                    exec_state=exec_state,
                    agent_key="AML",
                    fn=lambda: assess_aml_domain_result(prf=prf, evidence=ev),
                    max_retries=0,
                    on_agent_update=on_agent_update,
                )
            )
        else:
            mark_skipped(
                "AML",
                "Not in scope based on PRF (aml_relevance/payments/onboarding all false).",
                domain=RiskDomain.aml.value,
            )

    # Compliance (RBI)
    if is_selected("RBI_COMPLIANCE"):
        ev = evidence_for("compliance", _agent_query(RiskDomain.compliance, prf))
        domain_results_by_domain[RiskDomain.compliance].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="RBI_COMPLIANCE",
                fn=lambda: assess_compliance_domain_result(prf=prf, evidence=ev),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # RBI Governance Super (inherent regulatory/cyber posture) -> merge into compliance domain
    if is_selected("RBI_GOV_SUPER"):
        rbi_super_out = _with_retries(
            exec_state=exec_state,
            agent_key="RBI_GOV_SUPER_JSON",
            fn=lambda: assess_rbi_governance_super(prf=prf, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["RBI"] = rbi_super_out
        domain_results_by_domain[RiskDomain.compliance].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="RBI_GOV_SUPER",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.compliance,
                    score_0_100=int(rbi_super_out.get("risk_score", 0)),
                    confidence_0_1=float(rbi_super_out.get("confidence_score", 0.0)),
                    summary=str(rbi_super_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # Legal
    if is_selected("LEGAL"):
        ev = evidence_for("legal", _agent_query(RiskDomain.legal, prf))
        domain_results_by_domain[RiskDomain.legal].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="LEGAL",
                fn=lambda: assess_legal_domain_result(prf=prf, evidence=ev),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # Data Governance (treat as DPEP/privacy-related domain for current RiskDomain enum)
    if is_selected("DATA_GOV"):
        data_gov_in_scope = bool(exec_state["scope"].get("customer_data") or exec_state["scope"].get("cross_border"))
        if data_gov_in_scope:
            ev = evidence_for("data_gov", _agent_query(RiskDomain.dpep, prf))
            data_gov_out = _with_retries(
                exec_state=exec_state,
                agent_key="DATA_GOV_JSON",
                fn=lambda: assess_data_governance(prf=prf, evidence=ev),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
            phase2_agent_outputs["DATA_GOV"] = data_gov_out
            domain_results_by_domain[RiskDomain.dpep].append(
                _with_retries(
                    exec_state=exec_state,
                    agent_key="DATA_GOV",
                    fn=lambda: _payload_to_domain_result(domain=RiskDomain.dpep, payload=data_gov_out),
                    max_retries=0,
                    on_agent_update=on_agent_update,
                )
            )
        else:
            mark_skipped(
                "DATA_GOV",
                "Not in scope based on PRF (customer_data_involved=false and no cross-border indicator).",
                domain=RiskDomain.dpep.value,
            )

    # ITGC (maps to IT Security domain)
    if is_selected("ITGC"):
        ev = evidence_for("itgc", _agent_query(RiskDomain.it_security, prf))
        itgc_out = _with_retries(
            exec_state=exec_state,
            agent_key="ITGC_JSON",
            fn=lambda: assess_itgc(prf=prf, evidence=ev),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["ITGC"] = itgc_out
        domain_results_by_domain[RiskDomain.it_security].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="ITGC",
                fn=lambda: _payload_to_domain_result(domain=RiskDomain.it_security, payload=itgc_out),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # OWASP + NIST (maps to IT Security domain)
    if is_selected("OWASP"):
        owasp_out = _with_retries(
            exec_state=exec_state,
            agent_key="OWASP_JSON",
            fn=lambda: assess_owasp_security(prf=prf, architecture_description=prf.additional_context, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["OWASP"] = owasp_out
        domain_results_by_domain[RiskDomain.it_security].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="OWASP",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.it_security,
                    score_0_100=int(owasp_out.get("risk_score", 0)),
                    confidence_0_1=float(owasp_out.get("confidence_score", 0.0)),
                    summary=str(owasp_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    if is_selected("NIST"):
        nist_out = _with_retries(
            exec_state=exec_state,
            agent_key="NIST_JSON",
            fn=lambda: assess_nist_csf(prf=prf, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["NIST"] = nist_out
        domain_results_by_domain[RiskDomain.it_security].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="NIST",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.it_security,
                    score_0_100=int(nist_out.get("risk_score", 0)),
                    confidence_0_1=float(nist_out.get("confidence_score", 0.0)),
                    summary=str(nist_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # ISO + COBIT + IEEE (maps to governance_sdlc domain)
    if is_selected("ISO"):
        iso_out = _with_retries(
            exec_state=exec_state,
            agent_key="ISO_JSON",
            fn=lambda: assess_iso_governance(prf=prf, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["ISO"] = iso_out
        domain_results_by_domain[RiskDomain.governance_sdlc].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="ISO",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.governance_sdlc,
                    score_0_100=int(iso_out.get("risk_score", 0)),
                    confidence_0_1=float(iso_out.get("confidence_score", 0.0)),
                    summary=str(iso_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    if is_selected("COBIT"):
        cobit_out = _with_retries(
            exec_state=exec_state,
            agent_key="COBIT_JSON",
            fn=lambda: assess_cobit_governance(prf=prf, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["COBIT"] = cobit_out
        domain_results_by_domain[RiskDomain.governance_sdlc].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="COBIT",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.governance_sdlc,
                    score_0_100=int(cobit_out.get("risk_score", 0)),
                    confidence_0_1=float(cobit_out.get("confidence_score", 0.0)),
                    summary=str(cobit_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    if is_selected("IEEE"):
        ieee_out = _with_retries(
            exec_state=exec_state,
            agent_key="IEEE_JSON",
            fn=lambda: assess_ieee_governance(prf=prf, architecture_overview=prf.additional_context, evidence=[]),
            max_retries=0,
            on_agent_update=on_agent_update,
        )
        phase2_agent_outputs["IEEE"] = ieee_out
        domain_results_by_domain[RiskDomain.governance_sdlc].append(
            _with_retries(
                exec_state=exec_state,
                agent_key="IEEE",
                fn=lambda: DomainRiskResult(
                    domain=RiskDomain.governance_sdlc,
                    score_0_100=int(ieee_out.get("risk_score", 0)),
                    confidence_0_1=float(ieee_out.get("confidence_score", 0.0)),
                    summary=str(ieee_out.get("explainability_summary", "")),
                    findings=[],
                ),
                max_retries=0,
                on_agent_update=on_agent_update,
            )
        )

    # Final merged domain results
    domain_results: List[DomainRiskResult] = []
    for dom, results in domain_results_by_domain.items():
        merged = _merge_domain_results(dom, results)
        if merged.score_0_100 > 0 or merged.findings:
            domain_results.append(merged)

    report = new_report_skeleton(prf.project_name, domain_results)
    report.execution_state = exec_state

    # Enterprise pipeline artifacts
    mcl_mapping = _map_findings_to_mcl(domain_results)

    # Evidence engine stage: evidence uploads are not yet provided through the UI/CLI.
    # Keep deterministic empty validation output and rely on audit logs for traceability.
    evidence_validation: List[Dict[str, object]] = []

    # Sampling/testing stage
    # In full_audit mode, population_map must be passed externally (regulator-defensible).
    if execution_mode == "full_audit" and not population_map:
        raise ValueError("Population size required for statistical sampling.")

    inherent_score = float(report.enterprise_risk_score_0_100)
    inherent_level = _risk_level_label_from_score(inherent_score)

    per_control_sampling: List[Dict[str, Any]] = []
    control_effectiveness_values: List[float] = []

    # Derive control inventory from MCL mapping (control IDs).
    control_ids: List[str] = []
    for m in mcl_mapping:
        for cid in (m.get("mcl_control_ids") or []):
            if isinstance(cid, str):
                control_ids.append(cid)
    control_ids = sorted(set(control_ids))

    if execution_mode == "full_audit":
        assert population_map is not None
        missing = [cid for cid in control_ids if population_map.get(cid) is None]
        if missing:
            missing_str = ", ".join(missing[:30]) + ("" if len(missing) <= 30 else f" ... (+{len(missing) - 30} more)")
            raise ValueError(
                "Population map is missing required control IDs: "
                + missing_str
                + ". Provide a JSON object like {\"MCL-ACCESS-001\": 120, ...}"
            )

        for cid in control_ids:
            pop = population_map.get(cid)
            out = run_control_sampling(control_id=cid, population_size=int(pop), risk_level=inherent_level)  # type: ignore[arg-type]
            per_control_sampling.append(out)
            control_effectiveness_values.append(float(out.get("control_effectiveness", 0.0)))

    # If dry_run, keep sampling outputs empty and effectiveness at 0.0 (no guessing).
    sampling: Dict[str, Any] = {
        "execution_mode": execution_mode,
        "controls": per_control_sampling,
    }

    control_effectiveness = round(
        (sum(control_effectiveness_values) / len(control_effectiveness_values)),
        4,
    ) if control_effectiveness_values else 0.0
    report.control_effectiveness = control_effectiveness

    residual = compute_residual_risk(
        inherent_risk=float(inherent_score),
        control_effectiveness=float(control_effectiveness),
    )

    # Maturity assessment (deterministic): derive maturity from control effectiveness.
    maturity_scores = [round(max(0.0, min(5.0, control_effectiveness * 5.0)), 2)]
    maturity = assess_maturity(domain="Enterprise", control_scores_0_5=maturity_scores)

    # Reuse Phase 2 deterministic agent outputs for meta-governance input.
    iso_out = phase2_agent_outputs.get("ISO")
    cobit_out = phase2_agent_outputs.get("COBIT")
    nist_out = phase2_agent_outputs.get("NIST")
    rbi_out = phase2_agent_outputs.get("RBI")
    owasp_out = phase2_agent_outputs.get("OWASP")
    ieee_out = phase2_agent_outputs.get("IEEE")

    aml_out = _domain_result_to_agent_output(
        next((x for x in domain_results if x.domain == RiskDomain.aml), None)
        or DomainRiskResult(domain=RiskDomain.aml, score_0_100=0, confidence_0_1=0.0, summary="", findings=[])
    )
    legal_out = _domain_result_to_agent_output(
        next((x for x in domain_results if x.domain == RiskDomain.legal), None)
        or DomainRiskResult(domain=RiskDomain.legal, score_0_100=0, confidence_0_1=0.0, summary="", findings=[])
    )
    it_sec_out = _domain_result_to_agent_output(
        next((x for x in domain_results if x.domain == RiskDomain.it_security), None)
        or DomainRiskResult(domain=RiskDomain.it_security, score_0_100=0, confidence_0_1=0.0, summary="", findings=[])
    )

    meta = aggregate_enterprise_governance(
        iso_output=iso_out,
        cobit_output=cobit_out,
        nist_output=nist_out,
        rbi_output=rbi_out,
        owasp_output=owasp_out,
        it_security_output=it_sec_out,
        aml_output=aml_out,
        legal_output=legal_out,
        ieee_output=ieee_out,
        residual_risk_output=residual,
        maturity_output=maturity,
    )

    report.residual_risk = residual
    report.maturity = maturity
    report.mcl_control_mapping = mcl_mapping
    report.evidence_validation = evidence_validation
    report.sampling_testing = sampling
    report.enterprise_meta_governance = meta

    # Approval recommendation: use meta-governance recommendation if present.
    report.approval_recommendation = _map_meta_recommendation_to_report(str(meta.get("approval_recommendation", "")))

    log_agent_decision(
        agent_name="Enterprise Orchestrator",
        prf_project_name=prf.project_name,
        input_payload={"prf": prf.model_dump(), "scope": exec_state.get("scope")},
        output_payload={
            "domain_count": len(domain_results),
            "enterprise_risk_score": report.enterprise_risk_score_0_100,
            "approval_recommendation": report.approval_recommendation,
            "execution_state": exec_state,
        },
        risk_score_0_100=int(round(report.enterprise_risk_score_0_100)),
        confidence_0_1=0.6,
        domain="orchestrator",
    )

    genai_remediations = genai_governance_checks(prf)
    report.mandatory_remediation = sorted(set(report.mandatory_remediation + genai_remediations))

    return report
