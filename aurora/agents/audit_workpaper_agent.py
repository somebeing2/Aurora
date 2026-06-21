from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Sequence


ApprovalStatus = Literal["Draft", "In Review", "Approved", "Rejected"]


@dataclass(frozen=True)
class AuditWorkpaper:
    finding_id: str
    control_id: str
    risk_category: str
    issue_description: str
    impact_assessment: str
    root_cause: str
    recommendation: str
    management_response_placeholder: str
    target_date_placeholder: str
    evidence_reference: str
    reviewer_signature_placeholder: str
    approval_status: ApprovalStatus


def _now_utc_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _make_finding_id(*, control_id: str, issue_description: str) -> str:
    raw = f"{control_id}:{issue_description}".encode("utf-8")
    h = hashlib.sha256(raw).hexdigest()[:10].upper()
    return f"FND-{h}"


def generate_workpaper(
    *,
    control_id: str,
    risk_category: str,
    issue_description: str,
    impact_assessment: str,
    root_cause: str,
    recommendation: str,
    evidence_reference: str,
    approval_status: ApprovalStatus = "Draft",
) -> Dict[str, Any]:
    """Generate a regulator-ready structured audit workpaper (JSON only)."""

    wp = AuditWorkpaper(
        finding_id=_make_finding_id(control_id=control_id, issue_description=issue_description),
        control_id=str(control_id),
        risk_category=str(risk_category),
        issue_description=str(issue_description),
        impact_assessment=str(impact_assessment),
        root_cause=str(root_cause),
        recommendation=str(recommendation),
        management_response_placeholder="TBD - Management Response",
        target_date_placeholder="TBD - Target Remediation Date",
        evidence_reference=str(evidence_reference),
        reviewer_signature_placeholder="TBD - Reviewer Signature",
        approval_status=approval_status,
    )

    out = asdict(wp)
    out["generated_at_utc"] = _now_utc_iso()
    return out


def generate_workpapers_for_findings(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch convert findings to workpapers.

    Expected fields per finding dict:
    - control_id
    - risk_category
    - issue_description
    - impact_assessment
    - root_cause
    - recommendation
    - evidence_reference
    """

    out: List[Dict[str, Any]] = []
    for f in findings:
        out.append(
            generate_workpaper(
                control_id=str(f.get("control_id", "")),
                risk_category=str(f.get("risk_category", "")),
                issue_description=str(f.get("issue_description", "")),
                impact_assessment=str(f.get("impact_assessment", "")),
                root_cause=str(f.get("root_cause", "")),
                recommendation=str(f.get("recommendation", "")),
                evidence_reference=str(f.get("evidence_reference", "")),
                approval_status=str(f.get("approval_status", "Draft"))  # type: ignore[arg-type]
                if str(f.get("approval_status", "Draft")) in {"Draft", "In Review", "Approved", "Rejected"}
                else "Draft",
            )
        )
    return out
