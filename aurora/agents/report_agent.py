from __future__ import annotations

import os
from urllib.parse import urlparse

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_community.llms import Ollama

from aurora.models.risk_schema import EnterpriseRiskReport


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


def generate_executive_summary(report: EnterpriseRiskReport) -> str:
    llm = _ollama_llm()

    prompt = f"""You are generating an executive summary for a project risk review.

Input report JSON:
{report.model_dump_json(indent=2)}

Write:
- 6-12 bullet executive summary
- Approval recommendation rationale
- Mandatory remediation (top 8)
- Evidence references (sources)

Constraints:
- Be concise.
- Do not invent evidence sources not present in the report.
"""

    try:
        out = llm.invoke(prompt)
        return str(out).strip()
    except Exception as e:
        msg = str(e)
        model = os.getenv("OLLAMA_MODEL", "mistral:latest")
        if "OllamaEndpointNotFoundError" in msg or "status code 404" in msg or "model is not found" in msg.lower():
            return "\n".join(
                [
                    "Executive Summary (Fallback – LLM unavailable)",
                    "",
                    f"Reason: Ollama model '{model}' is not available locally.",
                    "Action: Pull the model and rerun the dashboard:",
                    f"  ollama pull {model}",
                    "",
                    f"Project: {report.prf_project_name}",
                    f"Enterprise Risk Score (0–100): {report.enterprise_risk_score_0_100}",
                    f"Recommendation: {report.approval_recommendation}",
                    f"Domains Assessed: {len(report.domain_results)}",
                    "",
                    "Top Mandatory Remediation:",
                    *[f"- {x}" for x in (report.mandatory_remediation or [])[:8]],
                    "",
                    "Evidence References:",
                    *[f"- {x}" for x in (report.evidence_references or [])[:12]],
                ]
            ).strip()

        return "\n".join(
            [
                "Executive Summary (Fallback – LLM error)",
                "",
                f"Project: {report.prf_project_name}",
                f"Enterprise Risk Score (0–100): {report.enterprise_risk_score_0_100}",
                f"Recommendation: {report.approval_recommendation}",
                "",
                f"Error: {type(e).__name__}: {msg}",
            ]
        ).strip()
