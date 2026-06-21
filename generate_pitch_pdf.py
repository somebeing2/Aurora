from fpdf import FPDF
from fpdf.enums import XPos, YPos


class PitchPDF(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 18, "F")
        self.set_text_color(99, 179, 237)
        self.set_font("Helvetica", "B", 10)
        self.set_xy(10, 5)
        self.cell(0, 8, "AURORA  -  Autonomous Unified Risk & Oversight Review Agent", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(30, 30, 30)

    def footer(self):
        self.set_y(-12)
        self.set_fill_color(15, 23, 42)
        self.rect(0, 285, 210, 12, "F")
        self.set_text_color(150, 180, 210)
        self.set_font("Helvetica", "", 8)
        self.set_xy(10, 287)
        self.cell(0, 6, f"AURORA Product Pitch  |  Page {self.page_no()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(30, 30, 30)

    def section_title(self, text):
        self.ln(4)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, f"  {text}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.set_text_color(30, 30, 30)
        self.ln(2)

    def sub_title(self, text):
        self.ln(3)
        self.set_text_color(30, 80, 160)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 6, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(30, 30, 30)
        self.ln(1)

    def body_text(self, text):
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def bullet(self, text):
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(40, 40, 40)
        self.set_x(self.l_margin + 4)
        self.cell(5, 5.5, "-", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.multi_cell(0, 5.5, text)

    def kv_row(self, key, value, shade=False):
        if shade:
            self.set_fill_color(235, 242, 252)
        else:
            self.set_fill_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(20, 20, 20)
        col1 = 55
        self.cell(col1, 6, f"  {key}", border=1, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 6, f"  {value}", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def build_pdf(output_path: str = "AURORA_Product_Pitch.pdf"):
    pdf = PitchPDF()
    pdf.set_margins(15, 22, 15)
    pdf.set_auto_page_break(auto=True, margin=18)

    # ── PAGE 1 ─────────────────────────────────────────────────────────────────
    pdf.add_page()

    # Hero title block
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 18, 210, 28, "F")
    pdf.set_xy(15, 22)
    pdf.set_text_color(99, 179, 237)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "AURORA", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_xy(15, 32)
    pdf.set_text_color(200, 220, 255)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, "Autonomous Unified Risk & Oversight Review Agent", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_xy(15, 39)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(160, 190, 230)
    pdf.cell(0, 6, "Product Pitch  |  Agentic AI & Advanced RAG Hackathon", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(30, 30, 30)
    pdf.set_xy(15, 48)

    # ── Problem ────────────────────────────────────────────────────────────────
    pdf.section_title("THE PROBLEM")
    pdf.body_text(
        "Enterprise IT governance is broken at scale. Every year, organizations initiate hundreds of software "
        "projects, each requiring review across legal exposure, regulatory compliance, data privacy, AML obligations, "
        "IT security posture, and SDLC governance controls. Today this review process is:"
    )
    for item in [
        "Slow - manually assembled across siloed domain experts, taking days to weeks per project.",
        "Inconsistent - subjective, undocumented, and non-reproducible across reviewers.",
        "Unauditable - lacking the structured evidence trails required by regulators (RBI, CISA, ISO, NIST).",
        "High-stakes - a missed AML control gap or an OWASP vulnerability can cost millions in fines.",
    ]:
        pdf.bullet(item)
    pdf.ln(2)
    pdf.body_text(
        "India's BFSI sector faces mounting pressure from the RBI, the DPDP Act 2023, and global frameworks "
        "(NIST CSF, ISO 27001, COBIT 5, OWASP) to demonstrate governance rigor before software goes live - not after."
    )

    # ── Solution ───────────────────────────────────────────────────────────────
    pdf.section_title("THE SOLUTION")
    pdf.body_text(
        "AURORA is a production-grade, multi-agent Agentic AI + Advanced RAG platform that autonomously reviews "
        "software Project Request Forms (PRFs) across six risk domains simultaneously, producing a structured, "
        "evidence-backed enterprise risk report in minutes - not weeks."
    )
    pdf.sub_title("Six Risk Domains Covered Simultaneously")
    domains = [
        "Legal Risk",
        "Regulatory Compliance Risk (RBI Master Circulars, DPDP Act)",
        "Data Protection & Privacy Risk (DPEP)",
        "Anti-Money Laundering (AML) Risk",
        "IT Security Risk (OWASP Top-10, NIST CSF)",
        "Governance & SDLC Control Risk (COBIT 5, ISO 27001, IEEE)",
    ]
    for d in domains:
        pdf.bullet(d)

    # ── Architecture ───────────────────────────────────────────────────────────
    pdf.section_title("ARCHITECTURE - BUILT FOR PRODUCTION, NOT DEMOS")

    pdf.sub_title("1  Advanced RAG - Contextual Fidelity at Scale")
    pdf.body_text(
        "Every agent is evidence-first. Before issuing any risk finding, each domain agent queries a ChromaDB "
        "vector store indexed over real regulatory circulars and policy documents. The top-3 retrieved clauses "
        "are mandatory evidence per finding. A confidence scoring engine derives reliability from retrieval "
        "relevance and evidence density. Hallucination detection heuristics flag non-evidenced or vague language "
        "before any output surfaces - ensuring contextual fidelity even under adversarial inputs."
    )

    pdf.sub_title("2  Multi-Agent Orchestration via CrewAI")
    pdf.body_text(
        "AURORA deploys 15+ specialized agents: Legal, Compliance, AML, IT Security, ITGC, NIST CSF, OWASP, "
        "COBIT, ISO, IEEE, RBI Governance Super Agent, Data Governance, Sampling & Testing, Maturity Assessment, "
        "and an Enterprise Meta-Governance Aggregator. Agents run in parallel; the aggregator deterministically "
        "computes an enterprise risk score from weighted domain scores - no LLM subjectivity in the final number."
    )

    pdf.sub_title("3  Governance Layer - Audit-Ready by Design")
    pdf.body_text(
        "Every agent decision is logged to an immutable .jsonl audit trail with timestamps, inputs, outputs, "
        "scores, and confidence. An explainability engine surfaces human-readable rationale per finding, making "
        "AURORA's outputs defensible to a regulator or board - not just readable by a developer."
    )

    # ── PAGE 2 ─────────────────────────────────────────────────────────────────
    pdf.add_page()

    # ── Real-World Utility ─────────────────────────────────────────────────────
    pdf.section_title("REAL-WORLD UTILITY")
    pdf.body_text(
        "AURORA targets a concrete, high-value enterprise workflow: the pre-implementation software risk gate. "
        "When a bank, fintech, or enterprise IT team wants to launch a new mobile banking app, payments service, "
        "or data platform, they submit a Project Request Form. AURORA ingests the PRF and returns within minutes:"
    )
    for item in [
        "Structured JSON + PDF risk report with domain-level and enterprise-level risk scores.",
        "Evidence-cited findings mapped to specific regulatory clauses.",
        "OWASP vulnerability flags, NIST CSF maturity gaps, and RBI governance deficiencies.",
        "Streamlit executive dashboard - risk heatmap, severity donut charts, per-agent audit cards.",
        "MCP server exposing all agents as callable tools for external orchestrators (Claude, LangGraph).",
    ]:
        pdf.bullet(item)

    pdf.sub_title("Quantified Value Proposition")
    metrics = [
        ("Review cycle time", "5-15 business days  ->  under 5 minutes"),
        ("Framework coverage", "6 risk domains + 8 regulatory frameworks in a single automated pass"),
        ("Audit-readiness", "Evidence trails satisfying RBI, DPDP, ISO 27001, and CISA requirements"),
        ("Data sovereignty", "Runs entirely on-premise via Ollama - zero data leaves the organization"),
    ]
    for i, (k, v) in enumerate(metrics):
        pdf.kv_row(k, v, shade=(i % 2 == 0))
    pdf.ln(3)

    # ── Differentiators ────────────────────────────────────────────────────────
    pdf.section_title("KEY DIFFERENTIATORS vs. BASIC RAG WRAPPERS")
    headers = [("Feature", 58), ("Basic Wrapper", 52), ("AURORA", 75)]
    rows = [
        ("Evidence citation", "Optional", "Mandatory - top-3 clauses per finding"),
        ("Hallucination control", "None", "Heuristic flags + confidence score"),
        ("Audit trail", "None", "Immutable .jsonl per agent decision"),
        ("Score determinism", "LLM-generated", "Deterministically computed from domain weights"),
        ("Framework coverage", "1", "NIST CSF, OWASP, COBIT, ISO, IEEE, RBI, AML, DPDP"),
        ("Deployment", "Cloud API", "On-premise, air-gapped capable"),
        ("Integration surface", "Chat UI", "MCP server, REST API, CLI, Streamlit dashboard"),
    ]
    # Header row
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    for label, w in headers:
        pdf.cell(w, 6.5, f"  {label}", border=1, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.ln()
    for i, (feat, basic, aurora) in enumerate(rows):
        fill = i % 2 == 0
        bg = (235, 242, 252) if fill else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.cell(58, 6, f"  {feat}", border=1, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.cell(52, 6, f"  {basic}", border=1, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(75, 6, f"  {aurora}", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # ── Stress Test ────────────────────────────────────────────────────────────
    pdf.section_title("STRESS TEST DESIGN")
    for item in [
        "Adversarial PRFs with vague or missing fields trigger hallucination flags and confidence penalties - "
        "the system degrades gracefully rather than fabricating confident answers.",
        "Retrieval stress: ChromaDB indexes extend live by dropping new circulars into aurora/data/circulars/ "
        "- no retraining required.",
        "Scale: domain agents are stateless and independently callable via MCP tools, enabling horizontal scaling.",
    ]:
        pdf.bullet(item)

    # ── Roadmap ────────────────────────────────────────────────────────────────
    pdf.section_title("GO-TO-MARKET & ROADMAP")
    pdf.body_text(
        "Target Users: Enterprise IT risk teams, GRC departments, internal audit functions, and technology risk "
        "consultancies in BFSI (Banking, Financial Services & Insurance)."
    )
    phases = [
        ("Phase 1 (Current)", "Pre-implementation software project risk gate for BFSI - on-premise via Streamlit + Ollama."),
        ("Phase 2", "Integration with JIRA, ServiceNow, and enterprise GRC platforms; PDF report generation with regulatory cross-reference appendices."),
        ("Phase 3", "Continuous monitoring - AURORA re-evaluates live projects against newly issued RBI/SEBI circulars automatically, alerting governance teams of compliance drift in real time."),
    ]
    for i, (phase, desc) in enumerate(phases):
        pdf.kv_row(phase, desc, shade=(i % 2 == 0))
    pdf.ln(3)

    # ── Closing ────────────────────────────────────────────────────────────────
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(15, pdf.get_y(), 180, 14, "F")
    pdf.set_xy(15, pdf.get_y() + 3)
    pdf.set_text_color(99, 179, 237)
    pdf.set_font("Helvetica", "BI", 10)
    pdf.cell(
        0, 8,
        "AURORA - From PRF submission to audit-ready risk report in minutes, not weeks.",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C",
    )

    pdf.output(output_path)
    print(f"PDF saved to: {output_path}")


if __name__ == "__main__":
    build_pdf()
