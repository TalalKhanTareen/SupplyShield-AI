from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from scanner.dependency_parser import parse_requirements
from scanner.vulnerability_checker import check_vulnerability
from scanner.risk_engine import calculate_risk, get_risk_level
from scanner.report_generator import generate_report


BASE_DIR = Path(__file__).resolve().parent
DEMO_FILE = BASE_DIR / "data" / "demo_requirements.txt"

st.set_page_config(
    page_title="SupplyShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
    .stApp { background: #0b1220; }
    [data-testid="stSidebar"] { background: #111c30; }
    .main-title { font-size: 2.5rem; font-weight: 800; color: #e8f1ff; }
    .sub-title { color: #9db2ce; font-size: 1rem; margin-bottom: 1.2rem; }
    .small-note { color: #9db2ce; font-size: 0.85rem; }
    div[data-testid="stMetric"] {
        background: #14243a;
        border: 1px solid #263c58;
        padding: 16px;
        border-radius: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

with st.sidebar:
    st.markdown("## 🛡️ SupplyShield AI")
    st.caption("Software supply-chain risk intelligence")
    st.divider()
    st.markdown("### Scan coverage")
    st.write("**Ecosystem:** Python / PyPI")
    st.write("**Intelligence:** OSV vulnerability database")
    st.write("**Analysis:** Dependency risk prioritization")
    st.info("Internet access is required to query OSV during a scan.")

st.markdown('<div class="main-title">SupplyShield AI</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Automated Software Supply Chain Security & Vulnerability Intelligence</div>',
    unsafe_allow_html=True
)

overview_left, overview_right = st.columns([3, 1])
with overview_left:
    st.write(
        "Audit a Python project's pinned dependencies, identify known "
        "vulnerabilities, prioritize remediation, and export an audit report."
    )
with overview_right:
    st.markdown("**Live intelligence**")
    st.markdown('<span style="color:#35c98a">● OSV API integration</span>', unsafe_allow_html=True)

st.divider()

default_manifest = DEMO_FILE.read_text(encoding="utf-8") if DEMO_FILE.exists() else ""
uploaded_file = st.file_uploader(
    "Upload a requirements.txt file",
    type=["txt"],
    help="Use exact package pins such as requests==2.31.0."
)

with st.expander("Or paste your dependency manifest / use the included demo"):
    pasted_manifest = st.text_area(
        "requirements.txt content",
        value=default_manifest,
        height=150
    )

manifest = (
    uploaded_file.getvalue().decode("utf-8", errors="replace")
    if uploaded_file is not None
    else pasted_manifest
)

scan_col, hint_col = st.columns([1, 3])
with scan_col:
    scan_clicked = st.button("🚀 Run Security Audit", type="primary", use_container_width=True)
with hint_col:
    st.caption("The included demo manifest is preloaded. You can scan it immediately.")

if scan_clicked:
    dependencies, parser_errors = parse_requirements(manifest)

    if not dependencies:
        st.session_state["scan_results"] = {
            "dependencies": [],
            "findings": [],
            "parser_errors": parser_errors,
            "scan_errors": [],
            "risk_score": 0,
            "completed": False
        }
        st.error("No supported, exactly pinned dependencies were found. Check the manifest and parsing issues below.")
    else:
        findings = []
        scan_errors = []
        progress = st.progress(0)
        status = st.empty()

        with st.spinner("Querying OSV and analyzing dependency risk..."):
            for index, dependency in enumerate(dependencies, start=1):
                status.write(
                    f"Checking {dependency['name']} {dependency['version']} "
                    f"({index}/{len(dependencies)})"
                )
                result = check_vulnerability(
                    dependency["name"],
                    dependency["version"],
                    dependency["ecosystem"]
                )

                if result["status"] == "success":
                    findings.extend(result["findings"])
                else:
                    scan_errors.append({
                        "package": dependency["name"],
                        "version": dependency["version"],
                        "error": result["error"]
                    })

                progress.progress(index / len(dependencies))

        risk_score = calculate_risk(findings)
        completed = len(scan_errors) == 0 and len(parser_errors) == 0

        st.session_state["scan_results"] = {
            "dependencies": dependencies,
            "findings": findings,
            "parser_errors": parser_errors,
            "scan_errors": scan_errors,
            "risk_score": risk_score,
            "completed": completed
        }
        status.success("Audit finished.")

if "scan_results" in st.session_state:
    results = st.session_state["scan_results"]
    dependencies = results["dependencies"]
    findings = results["findings"]
    parser_errors = results["parser_errors"]
    scan_errors = results["scan_errors"]
    risk_score = results["risk_score"]

    st.divider()
    st.header("Security Overview")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Dependencies Analyzed", len(dependencies))
    c2.metric("Vulnerabilities Found", len(findings))
    c3.metric("Risk Score", f"{risk_score}/100")
    c4.metric("Risk Classification", get_risk_level(risk_score))

    if findings:
        severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
        severity_counts = (
            pd.Series([item["severity"] for item in findings])
            .value_counts()
            .reindex(severity_order, fill_value=0)
        )
        chart_col, summary_col = st.columns([1.2, 1])
        with chart_col:
            st.subheader("Vulnerability Severity")
            chart_data = severity_counts[severity_counts > 0].rename_axis("Severity").reset_index(name="Count")
            fig = px.bar(
                chart_data,
                x="Severity",
                y="Count",
                color="Severity",
                text="Count",
                title="Findings by severity"
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e8f1ff",
                showlegend=False,
                margin=dict(l=10, r=10, t=45, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        with summary_col:
            st.subheader("Risk interpretation")
            st.write(f"**{get_risk_level(risk_score)} risk**")
            st.write(
                "The score is based on the severity weights of returned "
                "vulnerabilities and is capped at 100."
            )
            st.write("Prioritize Critical and High findings first.")
    elif results["completed"]:
        st.success("No matching known vulnerabilities were returned for the dependencies checked.")
    else:
        st.warning("No vulnerabilities were returned, but the audit is incomplete. Review verification errors before drawing conclusions.")

    tab_findings, tab_dependencies, tab_issues = st.tabs(
        ["Vulnerability Findings", "Dependencies", "Audit Issues"]
    )

    with tab_findings:
        if findings:
            display_findings = []
            for item in findings:
                display_findings.append({
                    "Package": item["package"],
                    "Installed": item["installed_version"],
                    "Vulnerability": item["vulnerability_id"],
                    "Severity": item["severity"],
                    "Fixed Version": item.get("fixed_version") or "Not supplied",
                    "Summary": item["summary"]
                })
            st.dataframe(pd.DataFrame(display_findings), use_container_width=True, hide_index=True)
            for item in findings:
                with st.expander(f"{item['vulnerability_id']} — {item['package']} ({item['severity']})"):
                    st.write(item["summary"])
                    if item.get("fixed_version"):
                        st.success(f"Suggested fixed version: {item['fixed_version']}")
                    if item.get("references"):
                        st.markdown("**References**")
                        for url in item["references"][:5]:
                            st.markdown(f"- {url}")
        else:
            st.info("There are no vulnerability findings to display.")

    with tab_dependencies:
        if dependencies:
            st.dataframe(
                pd.DataFrame([
                    {
                        "Package": item["name"],
                        "Pinned Version": item["version"],
                        "Ecosystem": item["ecosystem"]
                    }
                    for item in dependencies
                ]),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No dependencies were successfully parsed.")

    with tab_issues:
        if scan_errors:
            st.subheader("Dependencies not verified")
            st.dataframe(pd.DataFrame(scan_errors), use_container_width=True, hide_index=True)
        if parser_errors:
            st.subheader("Manifest parsing issues")
            st.dataframe(pd.DataFrame(parser_errors), use_container_width=True, hide_index=True)
        if not scan_errors and not parser_errors:
            st.success("No scan or manifest parsing errors were reported.")

    report_errors = parser_errors + scan_errors
    report = generate_report(dependencies, findings, report_errors, risk_score)
    st.download_button(
        "⬇️ Download JSON Audit Report",
        data=report,
        file_name="supplyshield-audit-report.json",
        mime="application/json",
        type="primary"
    )

st.divider()
st.markdown(
    '<div class="small-note">SupplyShield AI is a prototype for known-vulnerability discovery. '
    'A clean scan does not prove a dependency is secure or detect every malicious package.</div>',
    unsafe_allow_html=True
)
