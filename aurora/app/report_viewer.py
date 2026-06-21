from __future__ import annotations

import json
from typing import Any, Dict

import streamlit as st


def render_report_json(report: Dict[str, Any]) -> None:
    st.subheader("Executive Output")
    st.json(report)

    st.download_button(
        label="Download report JSON",
        data=json.dumps(report, indent=2).encode("utf-8"),
        file_name="aurora_report.json",
        mime="application/json",
    )
