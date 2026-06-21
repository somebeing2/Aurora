from __future__ import annotations

from typing import Dict, List

from aurora.models.risk_schema import (
    AggregationInputs,
    DomainRiskResult,
    RiskDomain,
    compute_enterprise_risk_score,
    recommendation_from_score,
)


def aggregate(domain_results: List[DomainRiskResult]) -> Dict[str, object]:
    domain_scores: Dict[RiskDomain, int] = {r.domain: r.score_0_100 for r in domain_results}

    score = compute_enterprise_risk_score(AggregationInputs(domain_scores=domain_scores))
    recommendation = recommendation_from_score(score)

    return {
        "enterprise_risk_score_0_100": score,
        "approval_recommendation": recommendation,
    }
