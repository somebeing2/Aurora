from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class ConfidenceInputs:
    retrieval_scores: Iterable[float | None]
    has_evidence: bool


def compute_confidence(inputs: ConfidenceInputs) -> float:
    scores = [s for s in inputs.retrieval_scores if s is not None]
    if not scores:
        base = 0.35
    else:
        avg = sum(scores) / max(len(scores), 1)
        base = 0.75 if avg <= 0.6 else 0.6

    if inputs.has_evidence:
        base += 0.15
    else:
        base -= 0.10

    if base < 0.0:
        return 0.0
    if base > 1.0:
        return 1.0
    return round(base, 2)
