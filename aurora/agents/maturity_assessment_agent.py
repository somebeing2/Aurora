from __future__ import annotations

from typing import Any, Dict, List, Sequence


_LEVELS = {
    1: "Ad Hoc",
    2: "Repeatable",
    3: "Defined",
    4: "Managed",
    5: "Optimized",
}


def _clamp_0_5(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 5.0:
        return 5.0
    return float(round(x, 2))


def _map_level(avg_score: float) -> str:
    # Map average to nearest integer maturity level 1..5
    rounded = int(round(avg_score))
    if rounded < 1:
        rounded = 1
    if rounded > 5:
        rounded = 5
    return _LEVELS[rounded]


def assess_maturity(*, domain: str, control_scores_0_5: Sequence[float]) -> Dict[str, Any]:
    """Deterministic capability maturity assessment.

    Inputs:
    - domain: name of the domain being assessed
    - control_scores_0_5: list of per-control maturity scores (0..5)

    Output JSON:
    {
      "domain": "...",
      "average_score": 3.2,
      "maturity_level": "Defined"
    }
    """

    scores: List[float] = [_clamp_0_5(float(s)) for s in (control_scores_0_5 or [])]

    if not scores:
        avg = 0.0
    else:
        avg = round(sum(scores) / len(scores), 2)

    return {
        "domain": str(domain),
        "average_score": avg,
        "maturity_level": _map_level(avg) if avg > 0 else "Ad Hoc",
    }
