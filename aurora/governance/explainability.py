from __future__ import annotations

from typing import List

from aurora.models.risk_schema import DomainFinding


def explain_findings(findings: List[DomainFinding], max_findings: int = 5) -> str:
    """Create a concise explainability summary suitable for audit evidence."""

    if not findings:
        return "No material findings identified based on available inputs and retrieved evidence."

    lines: List[str] = []
    for f in findings[:max_findings]:
        ev = ", ".join(sorted({e.source for e in f.evidence if e.source}))
        if ev:
            lines.append(f"{f.title}: {f.risk_level}. Evidence: {ev}.")
        else:
            lines.append(f"{f.title}: {f.risk_level}.")

    return " ".join(lines)
