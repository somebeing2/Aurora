from __future__ import annotations

import io
import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

stylable_container = None  # removed: use st.container(key=...) with CSS instead

try:
    from streamlit_elements import elements, mui  # type: ignore
except Exception:  # pragma: no cover
    elements = None
    mui = None

try:
    import plotly.express as px  # type: ignore
except Exception:  # pragma: no cover
    px = None

from aurora.agents.orchestrator import run_full_audit
from aurora.agents.report_agent import generate_executive_summary
from aurora.app.heatmap import plot_risk_heatmap
from aurora.app.report_viewer import render_report_json
from aurora.governance.audit_logger import _log_path
from aurora.models.prf_schema import ProjectRequestForm
from aurora.pdf_report import report_to_pdf_bytes


def _display_agent_key(agent_key: object) -> str:
    display_key = str(agent_key)
    if display_key.endswith("_JSON"):
        display_key = display_key[: -len("_JSON")] + "_PREAUDIT"
    return display_key


def _status_state(status: str | None) -> str:
    s = (status or "").lower().strip()
    if s in {"running"}:
        return "running"
    if s in {"completed", "complete", "success"}:
        return "complete"
    if s in {"failed", "error"}:
        return "error"
    if s in {"skipped"}:
        return "complete"
    return "running"


def _severity_bucket(x: object) -> str:
    s = ("" if x is None else str(x)).strip().lower()
    if s in {"critical"}:
        return "Critical"
    if s in {"high"}:
        return "High"
    if s in {"medium"}:
        return "Medium"
    if s in {"low"}:
        return "Low"
    return "Unknown"


def _read_uploaded_json(upload) -> Dict[str, Any]:
    raw = upload.read()
    return json.loads(raw.decode("utf-8"))


def _read_uploaded_pdf_text(upload) -> str:
    try:
        import pdfplumber  # type: ignore
    except Exception as e:
        raise RuntimeError(f"pdfplumber is required for PDF uploads: {e}")

    raw = upload.read()
    text_parts: List[str] = []
    with pdfplumber.open(io.BytesIO(raw)) as pdf:
        for p in pdf.pages:
            t = p.extract_text() or ""
            if t.strip():
                text_parts.append(t)
    return "\n\n".join(text_parts).strip()


def _extract_bool(text: str, patterns_true: List[str], patterns_false: List[str]) -> Optional[bool]:
    t = (text or "").lower()
    if any(re.search(p, t) for p in patterns_true):
        return True
    if any(re.search(p, t) for p in patterns_false):
        return False
    return None


def _parse_prf_from_text(text: str) -> Dict[str, Any]:
    t = (text or "").strip()

    def m(rx: str) -> Optional[str]:
        mm = re.search(rx, t, flags=re.IGNORECASE | re.MULTILINE)
        if not mm:
            return None
        return (mm.group(1) or "").strip()

    project_name = m(r"(?:Project\s*Name|Initiative\s*Name)\s*[:\-]\s*(.+)")
    business_owner = m(r"(?:Business\s*Owner|Sponsor|Owner)\s*[:\-]\s*(.+)")
    requesting_department = m(r"(?:Department|Requesting\s*Department)\s*[:\-]\s*(.+)")
    customer_impact = m(r"(?:Customer\s*Impact|Customer\s*Facing\s*Impact)\s*[:\-]\s*(.+)")
    hosting_model = m(r"(?:Hosting\s*Model|Hosting)\s*[:\-]\s*(cloud|on[_\- ]prem|hybrid)")
    if hosting_model:
        hosting_model = hosting_model.lower().replace("-", "_").replace(" ", "_")
        if hosting_model == "onprem":
            hosting_model = "on_prem"

    data_classification = m(r"(?:Data\s*Classification|Classification)\s*[:\-]\s*(public|internal|confidential|restricted)")
    if data_classification:
        data_classification = data_classification.lower()

    vendor_involvement = _extract_bool(
        t,
        patterns_true=[r"vendor\s*involvement\s*[:\-]\s*(yes|true)", r"third\s*party\s*[:\-]\s*(yes|true)"],
        patterns_false=[r"vendor\s*involvement\s*[:\-]\s*(no|false)", r"third\s*party\s*[:\-]\s*(no|false)"],
    )
    customer_data_involved = _extract_bool(
        t,
        patterns_true=[r"customer\s*data\s*involved\s*[:\-]\s*(yes|true)", r"pii\s*[:\-]\s*(yes|true)"],
        patterns_false=[r"customer\s*data\s*involved\s*[:\-]\s*(no|false)", r"pii\s*[:\-]\s*(no|false)"],
    )
    aml_relevance = _extract_bool(
        t,
        patterns_true=[r"aml\s*relevance\s*[:\-]\s*(yes|true)", r"kyc\s*[:\-]\s*(yes|true)"],
        patterns_false=[r"aml\s*relevance\s*[:\-]\s*(no|false)", r"kyc\s*[:\-]\s*(no|false)"],
    )
    genai_component = _extract_bool(
        t,
        patterns_true=[r"genai\s*component\s*[:\-]\s*(yes|true)", r"llm\s*[:\-]\s*(yes|true)"],
        patterns_false=[r"genai\s*component\s*[:\-]\s*(no|false)", r"llm\s*[:\-]\s*(no|false)"],
    )

    return {
        "project_name": project_name or "",
        "business_owner": business_owner or "",
        "requesting_department": requesting_department,
        "data_classification": data_classification or "confidential",
        "customer_data_involved": bool(customer_data_involved) if customer_data_involved is not None else False,
        "data_types": [],
        "hosting_model": hosting_model or "cloud",
        "cloud_provider": None,
        "data_residency_required": False,
        "vendor_involvement": bool(vendor_involvement) if vendor_involvement is not None else False,
        "vendors": [],
        "budget_usd": None,
        "expected_go_live_date": None,
        "regulatory_impact": "none",
        "regulatory_regimes": [],
        "security_assessment_status": "not_started",
        "pen_test_required": None,
        "aml_relevance": bool(aml_relevance) if aml_relevance is not None else False,
        "customer_impact": customer_impact or "",
        "sdlc_controls_in_place": False,
        "genai_component": bool(genai_component) if genai_component is not None else False,
        "genai_use_cases": [],
        "additional_context": "",
        "_raw_pdf_text": t[:6000],
    }


def _adapt_prf_json(payload: Dict[str, Any]) -> Dict[str, Any]:
    def _coalesce(obj: Dict[str, Any], keys: List[str]) -> Optional[Any]:
        for k in keys:
            if k in obj and obj.get(k) not in (None, ""):
                return obj.get(k)
        return None

    pm = payload.get("project_metadata") if isinstance(payload.get("project_metadata"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    hosting = payload.get("hosting") if isinstance(payload.get("hosting"), dict) else {}
    vendors = payload.get("vendors") if isinstance(payload.get("vendors"), list) else []

    project_name = _coalesce(pm, ["project_name", "initiative_name", "name", "project"]) or _coalesce(payload, ["project_name"]) or ""
    business_owner = _coalesce(pm, ["business_owner", "owner", "sponsor", "requester"]) or _coalesce(payload, ["business_owner"]) or ""
    customer_impact = _coalesce(pm, ["customer_impact", "impact", "description", "summary"]) or _coalesce(payload, ["customer_impact"]) or ""

    data_classification = (
        _coalesce(data, ["data_classification", "classification"]) or _coalesce(payload, ["data_classification"]) or "confidential"
    )

    customer_data_involved = _coalesce(data, ["customer_data_involved", "customer_data", "pii", "contains_pii"])
    if customer_data_involved is None:
        customer_data_involved = _coalesce(payload, ["customer_data_involved"])
    customer_data_involved = bool(customer_data_involved) if customer_data_involved is not None else False

    hosting_model = (
        _coalesce(hosting, ["hosting_model", "deployment_model", "hosting"]) or _coalesce(payload, ["hosting_model"]) or "cloud"
    )
    if isinstance(hosting_model, str):
        hosting_model = hosting_model.lower().replace("-", "_").replace(" ", "_")
        if hosting_model == "onprem":
            hosting_model = "on_prem"

    vendor_involvement = _coalesce(payload, ["vendor_involvement", "third_party_involvement", "third_party"])
    if vendor_involvement is None:
        vendor_involvement = bool(vendors)
    vendor_involvement = bool(vendor_involvement)

    return {
        "project_name": str(project_name or ""),
        "business_owner": str(business_owner or ""),
        "requesting_department": _coalesce(pm, ["requesting_department", "department"]) or payload.get("requesting_department"),
        "data_classification": str(data_classification or "confidential").lower(),
        "customer_data_involved": bool(customer_data_involved),
        "data_types": payload.get("data_types") if isinstance(payload.get("data_types"), list) else [],
        "hosting_model": str(hosting_model or "cloud"),
        "cloud_provider": _coalesce(hosting, ["cloud_provider", "provider"]) or payload.get("cloud_provider"),
        "data_residency_required": bool(payload.get("data_residency_required")) if payload.get("data_residency_required") is not None else False,
        "vendor_involvement": vendor_involvement,
        "vendors": payload.get("vendors") if isinstance(payload.get("vendors"), list) else [],
        "budget_usd": payload.get("budget_usd"),
        "expected_go_live_date": payload.get("expected_go_live_date"),
        "regulatory_impact": str(payload.get("regulatory_impact") or "none").lower(),
        "regulatory_regimes": payload.get("regulatory_regimes") if isinstance(payload.get("regulatory_regimes"), list) else [],
        "security_assessment_status": str(payload.get("security_assessment_status") or "not_started"),
        "pen_test_required": payload.get("pen_test_required"),
        "aml_relevance": bool(payload.get("aml_relevance")) if payload.get("aml_relevance") is not None else False,
        "customer_impact": str(customer_impact or ""),
        "sdlc_controls_in_place": bool(payload.get("sdlc_controls_in_place")) if payload.get("sdlc_controls_in_place") is not None else False,
        "genai_component": bool(payload.get("genai_component")) if payload.get("genai_component") is not None else False,
        "genai_use_cases": payload.get("genai_use_cases") if isinstance(payload.get("genai_use_cases"), list) else [],
        "additional_context": payload.get("additional_context"),
    }


def _fallback_project_name(upload_name: Optional[str]) -> str:
    if not upload_name:
        return "Unnamed Project"
    try:
        stem = Path(str(upload_name)).stem
    except Exception:
        stem = str(upload_name)
    stem = (stem or "").strip()
    return stem if len(stem) >= 3 else "Unnamed Project"


def _load_audit_log_df(max_rows: int = 2000) -> pd.DataFrame:
    p = _log_path()
    if not p.exists():
        return pd.DataFrame()

    rows = []
    with p.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

    return pd.DataFrame(rows)


def main() -> None:
    load_dotenv()

    st.set_page_config(page_title="AURORA – Risk Review", layout="wide")

    st.markdown(
        """
        <style>
          div[data-baseweb="tab-list"] {
            gap: 10px;
          }

          button[data-baseweb="tab"] {
            font-size: 1.05rem;
            font-weight: 600;
            padding: 10px 16px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.10);
          }

          button[data-baseweb="tab"]:hover {
            background: rgba(37, 99, 235, 0.12);
            border: 1px solid rgba(37, 99, 235, 0.35);
          }

          button[data-baseweb="tab"][aria-selected="true"] {
            background: rgba(37, 99, 235, 0.20);
            border: 1px solid rgba(37, 99, 235, 0.55);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
          }

          button[data-baseweb="tab"] p {
            font-size: 1.05rem;
            margin: 0;
          }

          div[data-testid="stMetricValue"] {
            font-size: 1.15rem;
            line-height: 1.2;
          }

          div[data-testid="stMetricLabel"] {
            font-size: 0.85rem;
            opacity: 0.85;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("""
    <style>
    [class*="st-key-aurora_header"] {
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: 14px;
      padding: 18px 18px 10px 18px;
      background: linear-gradient(135deg, rgba(37,99,235,0.18), rgba(17,27,46,0.60));
    }
    </style>
    """, unsafe_allow_html=True)
    with st.container(key="aurora_header"):
        st.title("AURORA")
        st.caption("Enterprise IT Governance | CISA-aligned audit | PRF pre-implementation risk review")

    execution_mode = "dry_run"
    population_map: Optional[Dict[str, int]] = None
    selected_agents: Optional[List[str]] = None
    prf: Optional[ProjectRequestForm] = None

    with st.sidebar:
        st.header("Controls")
        st.write("Upload a PRF JSON and run the autonomous review.")

        st.subheader("Execution Mode")
        execution_mode = st.selectbox(
            "Mode",
            options=["dry_run", "full_audit"],
            index=0,
            help="full_audit requires a population map (control_id -> population size).",
        )

        pop_upload = None
        if execution_mode == "full_audit":
            pop_upload = st.file_uploader("Upload population_map JSON", type=["json"], key="population_map")
            if pop_upload is not None:
                try:
                    population_payload = _read_uploaded_json(pop_upload)
                    if not isinstance(population_payload, dict):
                        raise ValueError("population_map must be a JSON object")
                    population_map = {str(k): int(v) for k, v in population_payload.items()}
                except Exception as e:
                    st.error(f"Invalid population_map JSON: {e}")

        st.subheader("Agent Selection")

        mandatory_agents = [
            ("RBI_COMPLIANCE", "RBI Compliance Agent (Deterministic)"),
            ("LEGAL", "Banking Legal Risk Agent (Deterministic)"),
            ("OWASP", "OWASP Security Review Agent (Deterministic)"),
            ("NIST", "NIST Cybersecurity Framework Agent (Deterministic)"),
            ("ISO", "ISO Governance Agent (Deterministic)"),
            ("COBIT", "COBIT Governance Agent (Deterministic)"),
            ("IEEE", "IEEE Standards Compliance Agent (Deterministic)"),
            ("ITGC", "ITGC Audit Agent (Deterministic)"),
        ]
        optional_agents = [
            ("AML", "AML Agent (Deterministic)"),
            ("DATA_GOV", "Data Governance Risk Assessment Agent (Deterministic)"),
            ("RBI_GOV_SUPER", "RBI Governance Super Agent (Deterministic)"),
        ]

        selected: List[str] = []
        st.caption("Mandatory agents are locked. Optional agents can be included/excluded per engagement scope.")

        with st.expander("Mandatory Agents", expanded=True):
            for key, label in mandatory_agents:
                st.checkbox(label, value=True, disabled=True, key=f"agent_{key}")
                selected.append(key)

        with st.expander("Optional Agents", expanded=True):
            for key, label in optional_agents:
                if st.checkbox(label, value=True, key=f"agent_{key}"):
                    selected.append(key)

        selected_agents = selected

    upload = st.file_uploader("Upload PRF (JSON or PDF)", type=["json", "pdf"])

    if upload is None and st.session_state.get("aurora_prf_payload") is None:
        st.info("Upload a PRF JSON/PDF to begin.")
        st.stop()

    if st.session_state.get("aurora_prf_payload") is None:
        payload: Dict[str, Any]
        assert upload is not None

        if upload.name.lower().endswith(".pdf"):
            try:
                pdf_text = _read_uploaded_pdf_text(upload)
            except Exception as e:
                st.error(str(e))
                st.stop()

            parsed = _parse_prf_from_text(pdf_text)
            with st.expander("PDF Extract (preview)", expanded=False):
                st.text(parsed.get("_raw_pdf_text", "") or "")

            st.subheader("PRF – Review extracted fields")
            with st.form("prf_pdf_form"):
                project_name = st.text_input("Project name", value=str(parsed.get("project_name", "")))
                business_owner = st.text_input("Business owner", value=str(parsed.get("business_owner", "")))
                requesting_department = st.text_input(
                    "Requesting department",
                    value=str(parsed.get("requesting_department") or ""),
                )
                data_classification = st.selectbox(
                    "Data classification",
                    options=["public", "internal", "confidential", "restricted"],
                    index=["public", "internal", "confidential", "restricted"].index(str(parsed.get("data_classification") or "confidential")),
                )
                customer_data_involved = st.checkbox(
                    "Customer/PII data involved",
                    value=bool(parsed.get("customer_data_involved")),
                )
                hosting_model = st.selectbox(
                    "Hosting model",
                    options=["cloud", "on_prem", "hybrid"],
                    index=["cloud", "on_prem", "hybrid"].index(str(parsed.get("hosting_model") or "cloud")),
                )
                vendor_involvement = st.checkbox(
                    "Vendor/third-party involvement",
                    value=bool(parsed.get("vendor_involvement")),
                )
                regulatory_impact = st.selectbox(
                    "Regulatory impact",
                    options=["none", "low", "medium", "high"],
                    index=["none", "low", "medium", "high"].index(str(parsed.get("regulatory_impact") or "none")),
                )
                aml_relevance = st.checkbox("AML relevance", value=bool(parsed.get("aml_relevance")))
                genai_component = st.checkbox("GenAI component", value=bool(parsed.get("genai_component")))
                customer_impact = st.text_area("Customer impact", value=str(parsed.get("customer_impact") or ""), height=120)
                additional_context = st.text_area(
                    "Additional context",
                    value=str(parsed.get("additional_context") or ""),
                    height=160,
                )
                submitted = st.form_submit_button("Use this PRF")

            if not submitted:
                st.info("Review the extracted fields and click 'Use this PRF' to continue.")
                st.stop()

            payload = {
                "project_name": project_name,
                "business_owner": business_owner,
                "requesting_department": requesting_department or None,
                "data_classification": data_classification,
                "customer_data_involved": customer_data_involved,
                "data_types": [],
                "hosting_model": hosting_model,
                "cloud_provider": None,
                "data_residency_required": False,
                "vendor_involvement": vendor_involvement,
                "vendors": [],
                "budget_usd": None,
                "expected_go_live_date": None,
                "regulatory_impact": regulatory_impact,
                "regulatory_regimes": [],
                "security_assessment_status": "not_started",
                "pen_test_required": None,
                "aml_relevance": aml_relevance,
                "customer_impact": customer_impact,
                "sdlc_controls_in_place": False,
                "genai_component": genai_component,
                "genai_use_cases": [],
                "additional_context": additional_context or None,
            }
        else:
            payload = _read_uploaded_json(upload)

            try:
                ProjectRequestForm.model_validate(payload)
            except Exception:
                adapted = _adapt_prf_json(payload)
                if not str(adapted.get("project_name") or "").strip():
                    adapted["project_name"] = _fallback_project_name(getattr(upload, "name", None))
                st.subheader("PRF – Review uploaded JSON fields")
                with st.form("prf_json_form"):
                    project_name = st.text_input("Project name", value=str(adapted.get("project_name", "")))
                    business_owner = st.text_input("Business owner", value=str(adapted.get("business_owner", "")))
                    requesting_department = st.text_input(
                        "Requesting department",
                        value=str(adapted.get("requesting_department") or ""),
                    )
                    data_classification = st.selectbox(
                        "Data classification",
                        options=["public", "internal", "confidential", "restricted"],
                        index=["public", "internal", "confidential", "restricted"].index(str(adapted.get("data_classification") or "confidential")),
                    )
                    customer_data_involved = st.checkbox(
                        "Customer/PII data involved",
                        value=bool(adapted.get("customer_data_involved")),
                    )
                    hosting_model = st.selectbox(
                        "Hosting model",
                        options=["cloud", "on_prem", "hybrid"],
                        index=["cloud", "on_prem", "hybrid"].index(str(adapted.get("hosting_model") or "cloud")),
                    )
                    vendor_involvement = st.checkbox(
                        "Vendor/third-party involvement",
                        value=bool(adapted.get("vendor_involvement")),
                    )
                    regulatory_impact = st.selectbox(
                        "Regulatory impact",
                        options=["none", "low", "medium", "high"],
                        index=["none", "low", "medium", "high"].index(str(adapted.get("regulatory_impact") or "none")),
                    )
                    aml_relevance = st.checkbox("AML relevance", value=bool(adapted.get("aml_relevance")))
                    genai_component = st.checkbox("GenAI component", value=bool(adapted.get("genai_component")))
                    customer_impact = st.text_area("Customer impact", value=str(adapted.get("customer_impact") or ""), height=120)
                    additional_context = st.text_area(
                        "Additional context",
                        value=str(adapted.get("additional_context") or ""),
                        height=160,
                    )
                    submitted = st.form_submit_button("Use this PRF")

                if not submitted:
                    st.info("Review the mapped fields and click 'Use this PRF' to continue.")
                    st.stop()

                payload = {
                    **adapted,
                    "project_name": project_name,
                    "business_owner": business_owner,
                    "requesting_department": requesting_department or None,
                    "data_classification": data_classification,
                    "customer_data_involved": customer_data_involved,
                    "hosting_model": hosting_model,
                    "vendor_involvement": vendor_involvement,
                    "regulatory_impact": regulatory_impact,
                    "aml_relevance": aml_relevance,
                    "genai_component": genai_component,
                    "customer_impact": customer_impact,
                    "additional_context": additional_context or None,
                }

        if not str(payload.get("project_name") or "").strip():
            payload["project_name"] = _fallback_project_name(getattr(upload, "name", None))

        try:
            prf = ProjectRequestForm.model_validate(payload)
        except Exception as e:
            st.error(f"PRF validation failed: {e}")
            st.json(payload)
            st.stop()

        st.session_state["aurora_prf_payload"] = prf.model_dump()

    prf = ProjectRequestForm.model_validate(st.session_state["aurora_prf_payload"])

    if st.button("Reset PRF", type="secondary"):
        st.session_state.pop("aurora_prf_payload", None)
        st.rerun()

    run_disabled = execution_mode == "full_audit" and not population_map
    if run_disabled:
        st.warning("Run analysis is disabled in full_audit mode until a population map is provided.")

    run_btn = st.button("Run analysis", type="primary", disabled=run_disabled)

    tabs = st.tabs(["Overview", "Live Run", "Findings", "Export"])

    report = None
    exec_summary = None
    report_dict: Dict[str, Any] | None = None

    live_exec_state: Dict[str, Any] = {
        "agents": {
            "STARTUP": {
                "status": "running",
                "attempt": 1,
                "meta": {"domain": "system", "reason": "Initializing run"},
            }
        }
    }

    table_ph = None
    status_ph = None
    progress_ph = None
    cards_ph = None

    def render_live() -> None:
        nonlocal table_ph, status_ph, progress_ph, cards_ph
        if table_ph is None or status_ph is None or progress_ph is None or cards_ph is None:
            return

        agents_state = live_exec_state.get("agents") if isinstance(live_exec_state, dict) else None
        if not isinstance(agents_state, dict) or not agents_state:
            table_ph.info("Waiting for agent execution to start...")
            return

        rows = []
        for agent_key, st_rec in agents_state.items():
            if not isinstance(st_rec, dict):
                continue
            meta = st_rec.get("meta") if isinstance(st_rec.get("meta"), dict) else {}
            rows.append(
                {
                    "agent": _display_agent_key(agent_key),
                    "status": st_rec.get("status"),
                    "attempt": st_rec.get("attempt"),
                    "domain": meta.get("domain"),
                    "score": meta.get("score"),
                    "confidence": meta.get("confidence"),
                    "findings": meta.get("findings_count"),
                    "reason": meta.get("reason"),
                }
            )

        total = len([r for r in rows if str(r.get("agent")) != "STARTUP"])
        completed = len(
            [
                r
                for r in rows
                if str(r.get("agent")) != "STARTUP" and _status_state(str(r.get("status") or "")) == "complete"
            ]
        )
        pct = 0.0 if total <= 0 else float(completed) / float(total)
        progress_ph.progress(pct, text=f"Progress: {completed}/{total} agents completed")

        with cards_ph.container():
            cols = st.columns(4)
            idx = 0
            for r in rows:
                if str(r.get("agent")) == "STARTUP":
                    continue
                title = str(r.get("agent"))
                domain = str(r.get("domain") or "")
                status = str(r.get("status") or "")
                sub = str(r.get("reason") or "")
                sub_html = (
                    f"<p style='font-size:0.75rem;opacity:0.7;margin:3px 0 0 0'>{sub}</p>"
                    if sub else ""
                )
                with cols[idx % 4]:
                    st.markdown(
                        f"""<div style="border:1px solid rgba(255,255,255,0.10);
                                        border-radius:14px;
                                        padding:12px 12px 10px 12px;
                                        background:rgba(255,255,255,0.03);
                                        margin-bottom:8px;">
                          <strong>{title}</strong>
                          <p style="font-size:0.8rem;opacity:0.8;margin:2px 0 0 0">{domain}</p>
                          <p style="margin:4px 0 0 0">Status: <code>{status}</code></p>
                          {sub_html}
                        </div>""",
                        unsafe_allow_html=True,
                    )
                idx += 1

        table_ph.dataframe(pd.DataFrame(rows), use_container_width=True)

        with status_ph.container():
            for r in rows:
                label = f"{r.get('agent')} — {r.get('status')}"
                state = _status_state(str(r.get("status") or ""))
                with st.status(label, state=state):
                    if r.get("reason"):
                        st.write(str(r.get("reason")))

    def on_agent_update(agent_key: str, record: Dict[str, Any]) -> None:
        agents = live_exec_state.get("agents")
        if not isinstance(agents, dict):
            agents = {}
            live_exec_state["agents"] = agents
        agents[str(agent_key)] = dict(record)
        render_live()

    with tabs[0]:
        st.subheader("PRF Summary")
        if elements is not None and mui is not None:
            with elements("kpi_cards"):
                with mui.Grid(container=True, spacing=2):
                    for title, value in [
                        ("Project", prf.project_name),
                        ("Owner", prf.business_owner),
                        ("Data", str(prf.data_classification)),
                        ("Hosting", str(prf.hosting_model)),
                    ]:
                        with mui.Grid(item=True, xs=12, sm=6, md=3):
                            with mui.Card(variant="outlined"):
                                with mui.CardContent(sx={"padding": "12px 14px"}):
                                    mui.Typography(
                                        title,
                                        variant="overline",
                                        sx={"opacity": 0.85, "fontSize": 11, "lineHeight": 1.1},
                                    )
                                    mui.Typography(
                                        str(value),
                                        variant="body2",
                                        noWrap=True,
                                        sx={"fontSize": 13, "fontWeight": 600, "lineHeight": 1.2},
                                    )
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Project", prf.project_name)
            c2.metric("Owner", prf.business_owner)
            c3.metric("Data", str(prf.data_classification))
            c4.metric("Hosting", str(prf.hosting_model))

        st.write(
            {
                "vendor_involvement": prf.vendor_involvement,
                "regulatory_impact": prf.regulatory_impact,
                "aml_relevance": prf.aml_relevance,
                "genai_component": prf.genai_component,
            }
        )

        if not run_btn:
            st.info("Configure inputs in the sidebar and click 'Run analysis' to start.")
            return

    with tabs[1]:
        st.subheader("Live Agent Execution")
        progress_ph = st.empty()
        cards_ph = st.empty()
        table_ph = st.empty()
        status_ph = st.empty()
        render_live()

    with st.spinner("Running multi-agent audit..."):
        try:
            report = run_full_audit(
                prf,
                execution_mode=execution_mode,
                population_map=population_map,
                selected_agents=selected_agents,
                on_agent_update=on_agent_update,
            )
        except ValueError as e:
            st.error(str(e))
            return

    live_exec_state["agents"]["STARTUP"]["status"] = "completed"
    render_live()

    report_dict = report.model_dump()

    with tabs[0]:
        st.subheader("Enterprise Risk Score")
        c1, c2, c3 = st.columns(3)
        c1.metric("Enterprise score (0–100)", f"{report.enterprise_risk_score_0_100:.2f}")
        c2.metric("Recommendation", report.approval_recommendation)
        c3.metric("Domains", len(report.domain_results))

        left, right = st.columns([1, 1])
        df_domain = pd.DataFrame(
            [
                {"domain": r.domain.value, "score": r.score_0_100, "confidence": r.confidence_0_1}
                for r in report.domain_results
            ]
        ).sort_values("score", ascending=False)

        with left:
            st.subheader("Domain Risk")
            if px is not None and not df_domain.empty:
                fig = px.bar(
                    df_domain,
                    x="score",
                    y="domain",
                    orientation="h",
                    text="score",
                    range_x=[0, 100],
                )
                fig.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.bar_chart(df_domain.set_index("domain")["score"], height=320)

        with right:
            st.subheader("Findings Severity")
            sev_rows: List[Dict[str, Any]] = []
            for dr in report.domain_results:
                for f in dr.findings:
                    sev_rows.append({"severity": _severity_bucket(f.risk_level)})
            df_sev = pd.DataFrame(sev_rows)
            if df_sev.empty:
                st.info("No findings were produced.")
            else:
                counts = df_sev["severity"].value_counts().reset_index()
                counts.columns = ["severity", "count"]
                if px is not None:
                    fig2 = px.pie(counts, names="severity", values="count", hole=0.55)
                    fig2.update_layout(height=320, margin=dict(l=10, r=10, t=20, b=10), legend_title_text="")
                    st.plotly_chart(fig2, use_container_width=True)
                else:
                    st.dataframe(counts, use_container_width=True)

        st.subheader("Top Mandatory Remediation")
        rem = list(report.mandatory_remediation or [])
        if not rem:
            st.write("No mandatory remediation items were generated.")
        else:
            st.write("\n".join([f"- {x}" for x in rem[:10]]))

        st.subheader("Domain Breakdown")
        df = pd.DataFrame(
            [
                {
                    "domain": r.domain.value,
                    "score": r.score_0_100,
                    "confidence": r.confidence_0_1,
                    "summary": r.summary,
                }
                for r in report.domain_results
            ]
        )
        st.dataframe(df, use_container_width=True)

    exec_state = report.execution_state or {}
    agents_state = exec_state.get("agents") if isinstance(exec_state, dict) else None
    if isinstance(agents_state, dict) and agents_state:
        rows = []
        for agent_key, st_rec in agents_state.items():
            if not isinstance(st_rec, dict):
                continue
            meta = st_rec.get("meta") if isinstance(st_rec.get("meta"), dict) else {}
            rows.append(
                {
                    "agent": _display_agent_key(agent_key),
                    "status": st_rec.get("status"),
                    "attempt": st_rec.get("attempt"),
                    "domain": meta.get("domain"),
                    "score": meta.get("score"),
                    "confidence": meta.get("confidence"),
                    "findings": meta.get("findings_count"),
                    "reason": meta.get("reason"),
                }
            )
        agent_df = pd.DataFrame(rows)

        with tabs[1]:
            if not agent_df.empty:
                st.caption("Agent-wise breakdown (execution state)")
                st.dataframe(agent_df, use_container_width=True)

        with tabs[2]:
            st.subheader("Risk Heatmap")
            fig = plot_risk_heatmap(report.domain_results)
            st.pyplot(fig, clear_figure=True)

            st.subheader("Executive Summary")
            with st.spinner("Generating executive summary..."):
                exec_summary = generate_executive_summary(report)
            st.text(exec_summary)

        with tabs[3]:
            pdf_bytes = report_to_pdf_bytes(report=report, executive_summary=exec_summary or "")
            st.download_button(
                label="Download PDF report",
                data=pdf_bytes,
                file_name="aurora_report.pdf",
                mime="application/pdf",
            )

            render_report_json(report_dict)

    st.divider()
    st.subheader("Audit Trail")
    log_df = _load_audit_log_df()
    if log_df.empty:
        st.write("No audit log events found yet.")
    else:
        st.dataframe(log_df, use_container_width=True)


if __name__ == "__main__":
    main()
