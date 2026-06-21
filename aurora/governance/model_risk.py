from __future__ import annotations

from typing import List

from aurora.models.prf_schema import ProjectRequestForm


def genai_governance_checks(prf: ProjectRequestForm) -> List[str]:
    """Enterprise GenAI governance checks.

    Produces required controls/remediations for projects that use GenAI.
    """

    if not prf.genai_component:
        return []

    remediations: List[str] = []
    remediations.append("Perform Model Risk Assessment (MRA) and document model purpose, limitations, and failure modes")
    remediations.append("Ensure prompt/response logging and retention align with data classification and privacy requirements")
    remediations.append("Implement human-in-the-loop for high-impact decisions and define escalation procedures")
    remediations.append("Validate that no restricted/PII is sent to external model endpoints without DPA and approvals")
    remediations.append("Establish red-teaming and safety testing for jailbreaks, leakage, and toxicity")
    return remediations
