from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from mcp.server.fastmcp import FastMCP

from aurora.agents.aml_agent import assess_aml_domain_result
from aurora.agents.cobit_governance_agent import assess_cobit_domain_result
from aurora.agents.compliance_agent import assess_compliance_domain_result
from aurora.agents.ieee_agent import assess_ieee_domain_result
from aurora.agents.iso_agent import assess_iso_domain_result
from aurora.agents.itgc_agent import assess_itgc_domain_result
from aurora.agents.it_security_agent import assess_it_security_domain_result
from aurora.agents.legal_agent import assess_legal_domain_result
from aurora.agents.nist_cyber_agent import assess_nist_domain_result
from aurora.agents.owasp_agent import assess_owasp_domain_result
from aurora.agents.orchestrator import run_full_audit
from aurora.agents.rbi_governance_super_agent import assess_rbi_governance_domain_result
from aurora.models.prf_schema import ProjectRequestForm
from aurora.models.risk_schema import DomainRiskResult, EnterpriseRiskReport
from aurora.rag.retriever import RetrievalHit, retrieve_clauses


mcp = FastMCP("aurora-agents")


def _prf_from_payload(payload: Dict[str, Any]) -> ProjectRequestForm:
    return ProjectRequestForm.model_validate(payload)


def _evidence_from_payload(evidence: Optional[Sequence[Dict[str, Any]]]) -> List[RetrievalHit]:
    if not evidence:
        return []
    out: List[RetrievalHit] = []
    for e in evidence:
        if not isinstance(e, dict):
            continue
        out.append(
            RetrievalHit(
                source=str(e.get("source") or ""),
                excerpt=str(e.get("excerpt") or ""),
                relevance_score=(float(e["relevance_score"]) if e.get("relevance_score") is not None else None),
            )
        )
    return out


def _dump(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # type: ignore[no-any-return]
    if isinstance(obj, dict):
        return obj
    return json.loads(json.dumps(obj, default=str))


@mcp.tool()
def retrieve_evidence(query: str, k: int = 3, collection_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve evidence clauses from the regulatory corpus (Chroma) for a query."""
    hits = retrieve_clauses(query, k=int(k), collection_name=collection_name)
    return [_dump(h) for h in hits]


@mcp.tool()
def assess_legal(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic Legal domain assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_legal_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_compliance(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic Compliance/RBI domain assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_compliance_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_aml(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic AML domain assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_aml_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_it_security(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic IT Security domain assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_it_security_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_itgc(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic IT General Controls (ITGC) assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_itgc_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_nist_csf(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic NIST CSF assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_nist_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_owasp(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic OWASP design/security review assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_owasp_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_cobit(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic COBIT governance assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_cobit_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_iso(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic ISO governance assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_iso_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_ieee(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic IEEE SDLC/standards governance assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_ieee_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def assess_rbi_governance_super(prf: Dict[str, Any], evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the deterministic RBI IT governance & cyber risk assessor."""
    prf_obj = _prf_from_payload(prf)
    ev = _evidence_from_payload(evidence)
    res: DomainRiskResult = assess_rbi_governance_domain_result(prf=prf_obj, evidence=ev)
    return res.model_dump()


@mcp.tool()
def run_enterprise_audit(
    prf: Dict[str, Any],
    execution_mode: str = "dry_run",
    selected_agents: Optional[List[str]] = None,
    data_root: str = "aurora/data",
    population_map: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Run the full AURORA audit pipeline (orchestrator) and return the EnterpriseRiskReport."""
    prf_obj = _prf_from_payload(prf)
    root = Path(data_root)
    report: EnterpriseRiskReport = run_full_audit(
        prf_obj,
        root,
        execution_mode=execution_mode,
        selected_agents=selected_agents,
        population_map=population_map,
        on_agent_update=None,
    )
    return report.model_dump()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
