from __future__ import annotations

from typing import Any, Dict, Literal, Union


ControlEffectivenessLabel = Literal["Effective", "Partially Effective", "Ineffective", "Absent"]


_EFFECTIVENESS: Dict[ControlEffectivenessLabel, float] = {
    "Effective": 0.8,
    "Partially Effective": 0.5,
    "Ineffective": 0.2,
    "Absent": 0.0,
}


def _clamp_0_100(x: float) -> int:
    if x < 0:
        return 0
    if x > 100:
        return 100
    return int(round(x))


def _clamp_0_1(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(round(x, 2))


def classify_residual_risk_level(residual_risk_0_100: int) -> str:
    if residual_risk_0_100 <= 20:
        return "Low"
    if residual_risk_0_100 <= 50:
        return "Medium"
    if residual_risk_0_100 <= 75:
        return "High"
    return "Critical"


def compute_residual_risk(
    *,
    inherent_risk: Union[int, float],
    control_effectiveness: Union[float, ControlEffectivenessLabel],
) -> Dict[str, Any]:
    """Residual_Risk = Inherent_Risk × (1 - Control_Effectiveness)

    Returns JSON-only dict:
    {
      "inherent_risk": 80,
      "control_effectiveness": 0.5,
      "residual_risk": 40,
      "risk_level": "Medium"
    }
    """

    inherent = _clamp_0_100(float(inherent_risk))

    if isinstance(control_effectiveness, str):
        eff = _EFFECTIVENESS.get(control_effectiveness, 0.0)
    else:
        eff = float(control_effectiveness)

    eff = _clamp_0_1(eff)

    residual = _clamp_0_100(inherent * (1.0 - eff))

    return {
        "inherent_risk": inherent,
        "control_effectiveness": eff,
        "residual_risk": residual,
        "risk_level": classify_residual_risk_level(residual),
    }
