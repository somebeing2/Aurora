from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DataClassification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class HostingModel(str, Enum):
    cloud = "cloud"
    on_prem = "on_prem"
    hybrid = "hybrid"


class RegulatoryImpact(str, Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


class SecurityAssessmentStatus(str, Enum):
    not_started = "not_started"
    in_progress = "in_progress"
    completed = "completed"
    not_applicable = "not_applicable"


class PRFVendor(BaseModel):
    name: str = Field(..., description="Vendor or third-party name")
    service_description: str = Field(..., description="What the vendor will provide")
    data_shared: bool = Field(..., description="Whether any enterprise/customer data will be shared with the vendor")
    country_of_processing: Optional[str] = Field(None, description="Primary country where the vendor will process/store data")


class ProjectRequestForm(BaseModel):
    project_name: str = Field(..., min_length=3)
    business_owner: str = Field(..., description="Accountable business owner")
    requesting_department: Optional[str] = None

    data_classification: DataClassification
    customer_data_involved: bool = Field(..., description="Whether customer/PII data is processed")
    data_types: List[str] = Field(default_factory=list, description="E.g., PII, PCI, PHI, transaction data")

    hosting_model: HostingModel
    cloud_provider: Optional[str] = Field(None, description="If hosting_model includes cloud")
    data_residency_required: bool = Field(False, description="Whether specific data residency constraints apply")

    vendor_involvement: bool
    vendors: List[PRFVendor] = Field(default_factory=list)

    budget_usd: Optional[float] = Field(None, ge=0)
    expected_go_live_date: Optional[str] = Field(None, description="ISO date string if available")

    regulatory_impact: RegulatoryImpact = RegulatoryImpact.none
    regulatory_regimes: List[str] = Field(default_factory=list, description="E.g., GDPR, GLBA, SOX, PCI DSS")

    security_assessment_status: SecurityAssessmentStatus = SecurityAssessmentStatus.not_started
    pen_test_required: Optional[bool] = None

    aml_relevance: bool = Field(False, description="Whether the initiative touches AML/KYC/transactions monitoring")
    customer_impact: str = Field(..., description="Describe customer impact and affected channels")

    sdlc_controls_in_place: bool = Field(
        False,
        description="Whether mandatory SDLC controls (code review, CI/CD approvals, change management) are in place",
    )

    genai_component: bool = Field(False, description="Whether this project uses GenAI/LLM or model-driven decisioning")
    genai_use_cases: List[str] = Field(default_factory=list)

    additional_context: Optional[str] = None
