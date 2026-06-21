from __future__ import annotations

from typing import List

from fpdf import FPDF

from aurora.models.risk_schema import DomainRiskResult, EnterpriseRiskReport


def _wrap_lines(text: str, max_len: int = 110) -> List[str]:
    raw_words = (text or "").split()
    words: List[str] = []
    for w in raw_words:
        if len(w) <= max_len:
            words.append(w)
            continue
        i = 0
        while i < len(w):
            chunk = w[i : i + max_len]
            words.append(chunk)
            i += max_len
    lines: List[str] = []
    cur: List[str] = []
    cur_len = 0
    for w in words:
        if cur_len + len(w) + 1 > max_len and cur:
            lines.append(" ".join(cur))
            cur = [w]
            cur_len = len(w)
        else:
            cur.append(w)
            cur_len += len(w) + 1
    if cur:
        lines.append(" ".join(cur))
    return lines


def _pdf_safe(text: str) -> str:
    t = text or ""
    # Replace common Unicode punctuation that FPDF core fonts cannot encode.
    t = t.replace("–", "-").replace("—", "-")
    t = t.replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    t = t.replace("•", "-")
    return t


def report_to_pdf_bytes(*, report: EnterpriseRiskReport, executive_summary: str) -> bytes:
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    usable_width = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 8, _pdf_safe("AURORA – Executive Risk Review"), ln=1)

    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 6, _pdf_safe(f"Project: {report.prf_project_name}"), ln=1)
    pdf.cell(0, 6, _pdf_safe(f"Generated (UTC): {report.generated_at_utc}"), ln=1)
    pdf.cell(0, 6, _pdf_safe(f"Enterprise Risk Score: {report.enterprise_risk_score_0_100:.2f}"), ln=1)
    pdf.cell(0, 6, _pdf_safe(f"Recommendation: {report.approval_recommendation}"), ln=1)

    pdf.ln(3)
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 7, _pdf_safe("Executive Summary"), ln=1)
    pdf.set_font("Helvetica", size=10)
    for line in executive_summary.splitlines():
        for wrapped in _wrap_lines(_pdf_safe(line), 115):
            pdf.multi_cell(usable_width, 5, wrapped)

    pdf.ln(2)
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 7, _pdf_safe("Domain Results"), ln=1)

    for dr in report.domain_results:
        pdf.set_font("Helvetica", style="B", size=11)
        pdf.cell(0, 6, _pdf_safe(f"{dr.domain.value} – score {dr.score_0_100} (confidence {dr.confidence_0_1:.2f})"), ln=1)
        pdf.set_font("Helvetica", size=10)
        for wrapped in _wrap_lines(_pdf_safe(dr.summary), 115)[:6]:
            pdf.multi_cell(usable_width, 5, wrapped)

        for f in dr.findings[:4]:
            pdf.set_font("Helvetica", style="B", size=10)
            pdf.multi_cell(usable_width, 5, _pdf_safe(f"- {f.title} ({f.risk_level})"))
            pdf.set_font("Helvetica", size=9)
            for wrapped in _wrap_lines(_pdf_safe(f.description), 120)[:5]:
                pdf.multi_cell(usable_width, 4.5, wrapped)

            if f.remediation:
                pdf.set_font("Helvetica", style="B", size=9)
                pdf.multi_cell(usable_width, 4.5, _pdf_safe("Remediation:"))
                pdf.set_font("Helvetica", size=9)
                for r in f.remediation[:4]:
                    pdf.multi_cell(usable_width, 4.5, _pdf_safe(f"  - {r}"))

            if f.evidence:
                pdf.set_font("Helvetica", style="B", size=9)
                pdf.multi_cell(usable_width, 4.5, _pdf_safe("Evidence:"))
                pdf.set_font("Helvetica", size=9)
                for e in f.evidence[:2]:
                    pdf.multi_cell(usable_width, 4.5, _pdf_safe(f"  - {e.source}"))

        pdf.ln(2)

    return bytes(pdf.output(dest="S"))
