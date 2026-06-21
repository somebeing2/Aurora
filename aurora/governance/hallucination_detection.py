from __future__ import annotations

import re
from typing import List

from aurora.models.risk_schema import DomainFinding


_VAGUE_PATTERNS = [
    r"\bmay\b",
    r"\bmight\b",
    r"\bpossibly\b",
    r"\bpotentially\b",
    r"\bgenerally\b",
    r"\boften\b",
    r"\busually\b",
    r"\bshould\b",
    r"\brecommend\b",
]


def governance_flags_for_finding(finding: DomainFinding) -> List[str]:
    """Heuristic governance flags.

    This is intentionally conservative and auditable:
    - Flags when evidence is missing.
    - Flags when language is vague (hallucination risk) without anchoring to evidence.

    The flags are used for governance oversight and do not change deterministic scoring.
    """

    flags: List[str] = []

    if not finding.evidence:
        flags.append("NO_EVIDENCE")

    text = f"{finding.title} {finding.description}".lower()
    vague_hits = sum(1 for p in _VAGUE_PATTERNS if re.search(p, text))

    if vague_hits >= 2:
        flags.append("VAGUE_LANGUAGE")

    if "unknown" in text or "tbd" in text or "to be decided" in text:
        flags.append("INSUFFICIENT_INPUTS")

    return flags
