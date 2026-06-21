from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Sequence

from aurora.agents.mcl_control_library_agent import get_control


EvidenceType = Literal[
    "Policy Document",
    "Log Extract",
    "Screenshot",
    "Configuration Export",
    "Report",
    "Contract",
]
ReviewStatus = Literal["Pending", "Accepted", "Rejected"]
YesNo = Literal["Yes", "No"]


@dataclass(frozen=True)
class EvidenceValidationResult:
    evidence_id: str
    linked_control_id: str
    evidence_type: EvidenceType
    upload_timestamp: str
    integrity_hash: str
    completeness_score: int
    relevance_score: int
    review_status: ReviewStatus
    reviewer_required: YesNo


def _now_utc_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _clamp_0_100(x: int) -> int:
    if x < 0:
        return 0
    if x > 100:
        return 100
    return x


def _contains_any(text: str, words: Sequence[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def classify_evidence_type(filename: str, declared_type: Optional[str] = None) -> EvidenceType:
    """Deterministic evidence type classification.

    Preference order:
    1) declared_type if it matches allowed types
    2) filename extension / keywords
    """

    allowed = {
        "policy document": "Policy Document",
        "log extract": "Log Extract",
        "screenshot": "Screenshot",
        "configuration export": "Configuration Export",
        "report": "Report",
        "contract": "Contract",
    }

    if declared_type:
        key = declared_type.strip().lower()
        if key in allowed:
            return allowed[key]  # type: ignore[return-value]

    name = (filename or "").lower()

    if name.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return "Screenshot"

    if name.endswith((".log", ".jsonl")) or "log" in name:
        return "Log Extract"

    if name.endswith((".yaml", ".yml", ".tf", ".json")) and _contains_any(name, ["config", "export", "terraform", "helm"]):
        return "Configuration Export"

    if _contains_any(name, ["msa", "sow", "dpa", "contract", "agreement"]):
        return "Contract"

    if _contains_any(name, ["policy", "standard", "procedure"]):
        return "Policy Document"

    if _contains_any(name, ["report", "assessment", "vapt", "pentest", "audit"]):
        return "Report"

    return "Report"


def _default_integrity_hash_placeholder() -> str:
    return "SHA256:NOT_COMPUTED"


def link_evidence_to_control(
    *,
    evidence_text: str,
    filename: str,
    suggested_control_id: Optional[str] = None,
) -> str:
    """Deterministic control linking.

    - If suggested_control_id exists in MCL, use it.
    - Else infer using simple keyword mapping against control categories.
    """

    if suggested_control_id:
        try:
            get_control(suggested_control_id)
            return suggested_control_id
        except Exception:
            pass

    text = f"{filename} {evidence_text}".lower()

    if _contains_any(text, ["risk assessment", "treatment", "residual risk"]):
        return "MCL-ISMS-001"
    if _contains_any(text, ["rbac", "abac", "iam", "mfa", "access review", "privileged"]):
        return "MCL-ACCESS-001"
    if _contains_any(text, ["encryption", "tls", "kms", "hsm", "key rotation"]):
        return "MCL-CRYPTO-001"
    if _contains_any(text, ["vendor", "supplier", "due diligence", "outsourcing", "audit rights", "msa", "sow", "dpa"]):
        return "MCL-SUPPLIER-001"
    if _contains_any(text, ["incident", "sirp", "soc", "security incident", "rbi reporting"]):
        return "MCL-INCIDENT-001"
    if _contains_any(text, ["bia", "rto", "rpo", "impact analysis"]):
        return "MCL-BCP-001"
    if _contains_any(text, ["disaster recovery", "dr drill", "failover", "backup", "restore"]):
        return "MCL-DR-001"
    if _contains_any(text, ["owasp", "sast", "dast", "secure coding", "code review", "dependency scanning"]):
        return "MCL-OWASP-001"
    if _contains_any(text, ["sqap", "verification", "validation", "traceability", "rtm"]):
        return "MCL-IEEE-001"
    if _contains_any(text, ["aml", "kyc", "sanctions", "pep", "str", "sar"]):
        return "MCL-AML-001"

    return "MCL-ISMS-001"


def score_completeness(*, evidence_type: EvidenceType, filename: str, evidence_text: str) -> int:
    """Deterministic completeness scoring."""

    name = (filename or "").lower()
    has_text = len((evidence_text or "").strip()) > 0

    if evidence_type == "Screenshot":
        return 55

    base = 35 if not has_text else 65

    if evidence_type == "Contract" and _contains_any(name, ["msa", "sow", "dpa", "agreement", "contract"]):
        base += 10

    if evidence_type == "Policy Document" and _contains_any(name, ["policy", "standard", "procedure"]):
        base += 10

    if evidence_type == "Log Extract" and _contains_any(name, ["log", "audit", "siem"]):
        base += 10

    return _clamp_0_100(base)


def score_relevance(*, linked_control_id: str, evidence_text: str, filename: str) -> int:
    """Deterministic relevance scoring to linked control."""

    text = f"{filename} {evidence_text}".lower()

    control_keywords: Dict[str, List[str]] = {
        "MCL-ISMS-001": ["risk assessment", "treatment", "residual", "risk register"],
        "MCL-ACCESS-001": ["rbac", "abac", "iam", "mfa", "least privilege", "access review"],
        "MCL-CRYPTO-001": ["encryption", "tls", "kms", "hsm", "key"],
        "MCL-SUPPLIER-001": ["vendor", "supplier", "outsourcing", "audit rights", "agreement", "msa", "sow", "dpa"],
        "MCL-INCIDENT-001": ["incident", "sirp", "soc", "runbook", "escalation", "reporting"],
        "MCL-BCP-001": ["bia", "impact", "rto", "rpo"],
        "MCL-DR-001": ["dr", "disaster", "backup", "restore", "failover", "recovery test"],
        "MCL-OWASP-001": ["owasp", "sast", "dast", "secure coding", "code review"],
        "MCL-IEEE-001": ["sqap", "rtm", "verification", "validation", "audit"],
        "MCL-AML-001": ["aml", "kyc", "sanctions", "pep", "str", "sar"],
    }

    kws = control_keywords.get(linked_control_id, [])
    hits = sum(1 for k in kws if k in text)

    if hits == 0:
        return 35
    if hits == 1:
        return 55
    if hits == 2:
        return 70
    return 85


def reviewer_required_for_type(evidence_type: EvidenceType) -> YesNo:
    if evidence_type in {"Contract", "Policy Document"}:
        return "Yes"
    return "No"


def validate_evidence_item(
    *,
    evidence_id: str,
    filename: str,
    upload_timestamp: Optional[str] = None,
    declared_type: Optional[str] = None,
    suggested_control_id: Optional[str] = None,
    evidence_text: str = "",
) -> Dict[str, Any]:
    """Validate, classify, and link a single evidence item."""

    et = classify_evidence_type(filename=filename, declared_type=declared_type)
    linked = link_evidence_to_control(
        evidence_text=evidence_text,
        filename=filename,
        suggested_control_id=suggested_control_id,
    )

    completeness = score_completeness(evidence_type=et, filename=filename, evidence_text=evidence_text)
    relevance = score_relevance(linked_control_id=linked, evidence_text=evidence_text, filename=filename)

    status: ReviewStatus = "Pending"
    if completeness < 40 or relevance < 40:
        status = "Rejected"

    reviewer_req = reviewer_required_for_type(et)

    result = EvidenceValidationResult(
        evidence_id=str(evidence_id),
        linked_control_id=str(linked),
        evidence_type=et,
        upload_timestamp=str(upload_timestamp or _now_utc_iso()),
        integrity_hash=_default_integrity_hash_placeholder(),
        completeness_score=_clamp_0_100(int(completeness)),
        relevance_score=_clamp_0_100(int(relevance)),
        review_status=status,
        reviewer_required=reviewer_req,
    )

    return asdict(result)


def validate_evidence_batch(evidence_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate a batch of evidence records.

    Each item may include:
    - evidence_id (required)
    - filename (required)
    - upload_timestamp
    - declared_type
    - suggested_control_id
    - evidence_text
    """

    out: List[Dict[str, Any]] = []
    for item in evidence_items:
        out.append(
            validate_evidence_item(
                evidence_id=str(item.get("evidence_id")),
                filename=str(item.get("filename")),
                upload_timestamp=item.get("upload_timestamp"),
                declared_type=item.get("declared_type"),
                suggested_control_id=item.get("suggested_control_id"),
                evidence_text=str(item.get("evidence_text", "")),
            )
        )
    return out


def evidence_gap_for_control(control_id: str) -> Dict[str, Any]:
    """Return an evidence-gap marker for a control (JSON only)."""

    return {
        "linked_control_id": control_id,
        "evidence_gap": True,
        "status": "Evidence Gap",
    }
