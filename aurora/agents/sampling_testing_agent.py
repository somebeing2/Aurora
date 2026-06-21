from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Literal, Tuple

import math


RiskLevel = Literal["Low", "Medium", "High", "Critical"]
TestResult = Literal["Pass", "Fail"]


_RISK_ADJUSTMENT = {"Low": 5, "Medium": 10, "High": 20, "Critical": 30}
_FAIL_RATE = {"Low": 0.05, "Medium": 0.10, "High": 0.20, "Critical": 0.30}


@dataclass(frozen=True)
class SampleTestItem:
    sample_id: str
    test_result: TestResult


def _seed(population_size: int, risk_level: RiskLevel) -> int:
    h = hashlib.sha256(f"{population_size}:{risk_level}".encode("utf-8")).hexdigest()
    return int(h[:12], 16)


def _seed_control(control_id: str, population_size: int, risk_level: RiskLevel) -> int:
    h = hashlib.sha256(f"{control_id}:{population_size}:{risk_level}".encode("utf-8")).hexdigest()
    return int(h[:12], 16)


def _clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))


def compute_sample_size(population_size: int, risk_level: RiskLevel) -> int:
    """Regulator-defensible deterministic sample size.

    Required formula:
    sample_size = ceil( sqrt(population_size) + risk_adjustment[risk_level] )
    """

    n = int(population_size)
    if n <= 0:
        return 0
    base = math.sqrt(n)
    adj = float(_RISK_ADJUSTMENT[risk_level])
    return _clamp_int(int(math.ceil(base + adj)), 1, n)


def generate_sample_identifiers(population_size: int, sample_size: int, rng: random.Random) -> List[str]:
    if population_size <= 0 or sample_size <= 0:
        return []

    picks = rng.sample(range(1, population_size + 1), k=min(sample_size, population_size))
    return [f"ITEM-{i:06d}" for i in sorted(picks)]


def assign_test_results(sample_ids: List[str], risk_level: RiskLevel, rng: random.Random) -> List[SampleTestItem]:
    fail_rate = _FAIL_RATE[risk_level]
    items: List[SampleTestItem] = []
    for sid in sample_ids:
        r = rng.random()
        items.append(SampleTestItem(sample_id=sid, test_result=("Fail" if r < fail_rate else "Pass")))
    return items


def run_sampling_test(*, population_size: int, risk_level: RiskLevel) -> Dict[str, Any]:
    """Run deterministic audit sampling and control test simulation.

    Output JSON:
    {
      "population_size": 10000,
      "sample_size": 120,
      "test_results_summary": {"pass": 110, "fail": 10},
      "control_effectiveness": 0.91
    }
    """

    pop = int(population_size)
    if pop <= 0:
        return {
            "population_size": 0,
            "sample_size": 0,
            "test_results_summary": {"pass": 0, "fail": 0},
            "control_effectiveness": 0.0,
            "samples": [],
        }

    ss = compute_sample_size(pop, risk_level)
    rng = random.Random(_seed(pop, risk_level))

    sample_ids = generate_sample_identifiers(pop, ss, rng)
    results = assign_test_results(sample_ids, risk_level, rng)

    passed = sum(1 for x in results if x.test_result == "Pass")
    failed = sum(1 for x in results if x.test_result == "Fail")

    effectiveness = 0.0 if ss == 0 else round(passed / ss, 2)

    return {
        "population_size": pop,
        "risk_level": risk_level,
        "sample_size": ss,
        "test_results_summary": {"pass": passed, "fail": failed},
        "control_effectiveness": effectiveness,
        "samples": [asdict(x) for x in results],
    }


def run_control_sampling(*, control_id: str, population_size: int, risk_level: RiskLevel) -> Dict[str, Any]:
    """Per-control sampling output (mandatory for Phase 4)."""

    pop = int(population_size)
    if pop <= 0:
        return {
            "control_id": str(control_id),
            "population_size": 0,
            "sample_size": 0,
            "pass_count": 0,
            "fail_count": 0,
            "control_effectiveness": 0.0,
        }

    ss = compute_sample_size(pop, risk_level)
    rng = random.Random(_seed_control(str(control_id), pop, risk_level))
    sample_ids = generate_sample_identifiers(pop, ss, rng)
    results = assign_test_results(sample_ids, risk_level, rng)

    pass_count = sum(1 for x in results if x.test_result == "Pass")
    fail_count = sum(1 for x in results if x.test_result == "Fail")
    ce = 0.0 if ss == 0 else round(pass_count / ss, 4)

    return {
        "control_id": str(control_id),
        "population_size": pop,
        "sample_size": ss,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "control_effectiveness": ce,
    }
