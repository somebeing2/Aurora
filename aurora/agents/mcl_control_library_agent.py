from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Literal, Optional


ControlType = Literal["Preventive", "Detective", "Corrective"]
AutomationLevel = Literal["Manual", "Semi", "Automated"]
RiskRating = Literal["Low", "Medium", "High", "Critical"]


@dataclass(frozen=True)
class MasterControl:
    control_id: str
    control_name: str
    control_objective: str
    control_description: str
    control_type: ControlType
    control_frequency: str
    control_owner_role: str
    automation_level: AutomationLevel
    inherent_risk_category: str
    mapped_frameworks: List[str]
    mapped_framework_references: List[str]
    risk_rating: RiskRating
    maturity_level: int


def _controls() -> List[MasterControl]:
    """Deterministic master control library.

    Note: Framework references are intentionally high-level (no clause numbers).
    """

    return [
        MasterControl(
            control_id="MCL-ISMS-001",
            control_name="Information Security Risk Assessment & Treatment",
            control_objective="Identify and treat information security risks before implementation.",
            control_description="Perform a documented IS risk assessment for the project, define risk owners, select treatments, and record residual risk acceptance.",
            control_type="Preventive",
            control_frequency="Per project / per material change",
            control_owner_role="CISO / Information Security",
            automation_level="Manual",
            inherent_risk_category="Information Security",
            mapped_frameworks=["ISO 27001", "NIST CSF", "COBIT", "RBI"],
            mapped_framework_references=[
                "ISO/IEC 27001 (ISMS risk management)",
                "NIST CSF Identify",
                "COBIT Risk Optimization",
                "RBI IT Governance expectations",
            ],
            risk_rating="High",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-ACCESS-001",
            control_name="Access Control Policy & RBAC Enforcement",
            control_objective="Ensure access is authorized, least-privileged, and auditable.",
            control_description="Define an access control policy, implement RBAC/ABAC where applicable, enforce MFA for privileged access, and review access periodically.",
            control_type="Preventive",
            control_frequency="Quarterly (review) + continuous enforcement",
            control_owner_role="IAM Team / Security",
            automation_level="Semi",
            inherent_risk_category="Access Control",
            mapped_frameworks=["ISO 27001", "NIST CSF", "OWASP", "RBI"],
            mapped_framework_references=[
                "ISO/IEC 27001 (access control)",
                "NIST CSF Protect",
                "OWASP API Security Top 10 (authorization)",
                "RBI Cyber Security expectations",
            ],
            risk_rating="High",
            maturity_level=3,
        ),
        MasterControl(
            control_id="MCL-CRYPTO-001",
            control_name="Cryptography Standard & Key Management",
            control_objective="Protect sensitive data using approved cryptography and managed keys.",
            control_description="Define encryption requirements for data at rest and in transit, approved algorithms, key ownership, rotation, and KMS/HSM usage.",
            control_type="Preventive",
            control_frequency="Continuous",
            control_owner_role="Security Architecture",
            automation_level="Semi",
            inherent_risk_category="Cryptography",
            mapped_frameworks=["ISO 27001", "NIST CSF", "OWASP", "RBI"],
            mapped_framework_references=[
                "ISO/IEC 27001 (cryptographic controls)",
                "NIST CSF Protect",
                "OWASP Top 10 – Web Applications (cryptography/data protection)",
                "RBI Cyber Security expectations",
            ],
            risk_rating="High",
            maturity_level=3,
        ),
        MasterControl(
            control_id="MCL-SUPPLIER-001",
            control_name="Supplier Security Due Diligence & Contractual Safeguards",
            control_objective="Ensure third parties meet security and audit requirements.",
            control_description="Perform supplier due diligence (security, privacy, resiliency), define contract clauses for audit rights, incident notification SLAs, and exit strategy.",
            control_type="Preventive",
            control_frequency="Per vendor onboarding + annual review",
            control_owner_role="Vendor Risk / Procurement / Security",
            automation_level="Manual",
            inherent_risk_category="Supplier Security",
            mapped_frameworks=["ISO 27001", "COBIT", "RBI", "Legal"],
            mapped_framework_references=[
                "ISO/IEC 27001 (supplier relationships)",
                "COBIT Resource Optimization",
                "RBI Outsourcing of IT Services Directions",
                "Indian contract governance practices",
            ],
            risk_rating="Critical",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-INCIDENT-001",
            control_name="Incident Response & Regulatory Reporting",
            control_objective="Ensure incidents are detected, managed, and reported within timelines.",
            control_description="Define incident response plan (roles, runbooks, escalation), integrate monitoring/alerting, and define regulatory reporting workflow where applicable.",
            control_type="Corrective",
            control_frequency="Continuous + semi-annual tabletop",
            control_owner_role="SOC / CISO / Compliance",
            automation_level="Semi",
            inherent_risk_category="Incident Management",
            mapped_frameworks=["ISO 27001", "NIST CSF", "RBI", "COBIT"],
            mapped_framework_references=[
                "ISO/IEC 27001 (incident management)",
                "NIST CSF Respond",
                "RBI cyber incident reporting expectations",
                "COBIT DSS (deliver/service/support)",
            ],
            risk_rating="Critical",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-BCP-001",
            control_name="Business Impact Analysis (BIA) & Recovery Objectives",
            control_objective="Define impact tolerances and recovery targets for critical services.",
            control_description="Perform BIA, identify dependencies, define RTO/RPO targets, and align DR strategy to business criticality.",
            control_type="Preventive",
            control_frequency="Annual + per major change",
            control_owner_role="BCM / IT Operations",
            automation_level="Manual",
            inherent_risk_category="Business Continuity",
            mapped_frameworks=["ISO 22301", "NIST CSF", "COBIT"],
            mapped_framework_references=[
                "ISO 22301 (BCMS)",
                "NIST CSF Recover",
                "COBIT Benefits Delivery",
            ],
            risk_rating="High",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-DR-001",
            control_name="Disaster Recovery Plan & Recovery Testing",
            control_objective="Ensure recoverability is planned, tested, and evidenced.",
            control_description="Document DR runbooks, backups, failover/failback procedures, and conduct recovery testing with remediation tracking.",
            control_type="Corrective",
            control_frequency="Quarterly (testing) + continuous readiness",
            control_owner_role="IT Operations / SRE",
            automation_level="Semi",
            inherent_risk_category="Disaster Recovery",
            mapped_frameworks=["ISO 22301", "NIST CSF", "RBI"],
            mapped_framework_references=[
                "ISO 22301 (recovery)",
                "NIST CSF Recover",
                "RBI cyber resilience expectations",
            ],
            risk_rating="Critical",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-OWASP-001",
            control_name="Secure SDLC AppSec Controls (OWASP)",
            control_objective="Reduce application security defects before go-live.",
            control_description="Define secure coding standards, mandatory code review, SAST/DAST (as applicable), dependency scanning, and secure configuration baselines.",
            control_type="Preventive",
            control_frequency="Per release / continuous",
            control_owner_role="AppSec / Engineering",
            automation_level="Semi",
            inherent_risk_category="Application Security",
            mapped_frameworks=["OWASP", "IEEE", "ISO 27001", "COBIT"],
            mapped_framework_references=[
                "OWASP Top 10 – Web Applications",
                "OWASP API Security Top 10",
                "IEEE 12207 (lifecycle processes)",
                "ISO/IEC 27001 (secure development)",
            ],
            risk_rating="High",
            maturity_level=3,
        ),
        MasterControl(
            control_id="MCL-IEEE-001",
            control_name="SQA Plan, V&V Plan, and Review Milestones",
            control_objective="Ensure quality planning, verification, validation, and audits are defined.",
            control_description="Create SQAP, define V&V approach (including independence), establish review/audit milestones, and maintain traceability from requirements to tests.",
            control_type="Detective",
            control_frequency="Per project",
            control_owner_role="QA / PMO / Engineering",
            automation_level="Manual",
            inherent_risk_category="SDLC Governance",
            mapped_frameworks=["IEEE", "COBIT"],
            mapped_framework_references=[
                "IEEE 730 (SQA)",
                "IEEE 1012 (V&V)",
                "IEEE 1028 (reviews/audits)",
                "COBIT Performance Monitoring",
            ],
            risk_rating="High",
            maturity_level=2,
        ),
        MasterControl(
            control_id="MCL-AML-001",
            control_name="AML/KYC Control Mapping for Relevant Systems",
            control_objective="Ensure AML/KYC controls are defined for systems impacting onboarding/transactions.",
            control_description="Define KYC workflow, sanctions/PEP screening, transaction monitoring requirements, STR trigger workflow, escalation, and auditability.",
            control_type="Preventive",
            control_frequency="Per project / continuous monitoring for AML systems",
            control_owner_role="AML Compliance / Financial Crime",
            automation_level="Manual",
            inherent_risk_category="Financial Crime",
            mapped_frameworks=["AML regulations", "RBI"],
            mapped_framework_references=[
                "RBI Master Directions on KYC",
                "PMLA obligations (high-level)",
            ],
            risk_rating="Critical",
            maturity_level=2,
        ),
    ]


def list_controls() -> List[Dict[str, Any]]:
    return [asdict(c) for c in _controls()]


def get_control(control_id: str) -> Dict[str, Any]:
    for c in _controls():
        if c.control_id == control_id:
            return asdict(c)
    raise KeyError(f"Unknown control_id: {control_id}")


def minimal_control_json(control_id: str) -> Dict[str, Any]:
    """Return minimal JSON output contract for a single control."""

    c = get_control(control_id)
    return {
        "control_id": c["control_id"],
        "control_name": c["control_name"],
        "control_objective": c["control_objective"],
        "framework_mappings": list(c["mapped_frameworks"]),
        "risk_rating": c["risk_rating"],
        "maturity_level": c["maturity_level"],
    }
