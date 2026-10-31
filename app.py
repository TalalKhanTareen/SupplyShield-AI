from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from scanner.dependency_parser import parse_requirements
from scanner.enrichment import (
    enrich_findings,
    get_epss_scores,
    get_kev_catalog,
    get_package_info,
)
from scanner.report_generator import generate_report
from scanner.risk_engine import calculate_risk, get_priority, get_risk_level, sort_findings
from scanner.vulnerability_checker import check_vulnerability


BASE_DIR = Path(__file__).resolve().parent
DEMO_FILE = BASE_DIR / "data" / "demo_requirements.txt"

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#3b82f6",
    "Unknown": "#64748b",
}
RISK_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#3b82f6",
    "No known findings": "#22c55e",
}

st.set_page_config(
    page_title="SupplyShield AI | Dependency Security Audit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    #MainMenu, footer { visibility: hidden; }
    .block-container { padding-top: 2rem; max-width: 1200px; }

    .hero {
        background: linear-gradient(135deg, #12223d 0%, #0b1220 70%);
        border: 1px solid #22385a;
        border-radius: 16px;
        padding: 28px 32px;
        margin-bottom: 1.2rem;
    }
    .hero h1 { margin: 0; font-size: 2.1rem; font-weight: 800; color: #f1f6ff; }
    .hero p  { margin: 6px 0 0 0; color: #9db2ce; font-size: 1.02rem; }

    .pill {
        display: inline-block; padding: 2px 10px; margin: 0 6px 4px 0;
        border-radius: 999px; font-size: 0.75rem; font-weight: 600;
        border: 1px solid #2c4468; color: #b7c9e4; background: #13233b;
    }
    .pill.on  { border-color: #1f6f4a; color: #4ade80; background: #0f2a20; }
    .pill.off { border-color: #4b5563; color: #94a3b8; }

    div[data-testid="stMetric"] {
        background: #111c30; border: 1px solid #22385a;
        padding: 16px 18px; border-radius: 12px;
    }
    div[data-testid="stMetricLabel"] { color: #9db2ce; }

    .small-note { color: #7f93b2; font-size: 0.82rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Cached wrappers so repeated scans do not hammer the free public APIs
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=3600, show_spinner=False)
def cached_osv(name, version, ecosystem):
    return check_vulnerability(name, version, ecosystem)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_pypi(name, version):
    return get_package_info(name, version)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_epss(cve_ids):
    return get_epss_scores(list(cve_ids))


@st.cache_data(ttl=3600, show_spinner=False)
def cached_kev():
    return get_kev_catalog()


def cached_epss_lookup(cve_ids):
    return cached_epss(tuple(sorted(cve_ids)))


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown("## 🛡️ SupplyShield AI")
    st.caption("Software supply-chain risk intelligence")
    st.divider()

    st.markdown("### Scan options")
    use_enrichment = st.toggle(
        "Threat-intel enrichment",
        value=True,
        help="Adds EPSS exploit probability, CISA KEV status and PyPI "
        "latest-version checks. All sources are free and need no API key.",
    )

    st.markdown("### Data sources")
    st.markdown(
        '<span class="pill on">OSV.dev</span>'
        f'<span class="pill {"on" if use_enrichment else "off"}">PyPI</span>'
        f'<span class="pill {"on" if use_enrichment else "off"}">FIRST EPSS</span>'
        f'<span class="pill {"on" if use_enrichment else "off"}">CISA KEV</span>',
        unsafe_allow_html=True,
    )
    st.caption("Ecosystem: Python / PyPI")
    st.info("Internet access is required to query the public APIs during a scan.")


# --------------------------------------------------------------------------- #
# Header + input
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <div class="hero">
      <h1>SupplyShield AI</h1>
      <p>Audit pinned Python dependencies for known vulnerabilities, prioritise
      remediation with real-world exploit data, and export an audit report.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

default_manifest = DEMO_FILE.read_text(encoding="utf-8") if DEMO_FILE.exists() else ""

input_tab, paste_tab = st.tabs(["Upload manifest", "Paste or use demo"])
with input_tab:
    uploaded_file = st.file_uploader(
        "Upload a requirements.txt file",
        type=["txt"],
        help="Use exact package pins such as requests==2.31.0.",
    )
with paste_tab:
    pasted_manifest = st.text_area(
        "requirements.txt content", value=default_manifest, height=150
    )

manifest = (
    uploaded_file.getvalue().decode("utf-8", errors="replace")
    if uploaded_file is not None
    else pasted_manifest
)

scan_col, hint_col = st.columns([1, 3])
with scan_col:
    scan_clicked = st.button("Run security audit", type="primary", width="stretch")
with hint_col:
    st.caption("The demo manifest is preloaded, so you can scan immediately.")


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
if scan_clicked:
    dependencies, parser_errors = parse_requirements(manifest)

    if not dependencies:
        st.session_state["scan_results"] = {
            "dependencies": [],
            "findings": [],
            "parser_errors": parser_errors,
            "scan_errors": [],
            "warnings": [],
            "risk_score": 0,
            "completed": False,
            "enriched": False,
        }
        st.error(
            "No supported, exactly pinned dependencies were found. "
            "Check the manifest and parsing issues below."
        )
    else:
        findings, scan_errors, warnings = [], [], []
        progress = st.progress(0)
        status = st.empty()

        with st.spinner("Querying vulnerability intelligence..."):
            for index, dependency in enumerate(dependencies, start=1):
                status.write(
                    f"Checking {dependency['name']} {dependency['version']} "
                    f"({index}/{len(dependencies)})"
                )
                result = cached_osv(
                    dependency["name"], dependency["version"], dependency["ecosystem"]
                )

                if result["status"] == "success":
                    findings.extend(result["findings"])
                else:
                    scan_errors.append({
                        "package": dependency["name"],
                        "version": dependency["version"],
                        "error": result["error"],
                    })

                if use_enrichment:
                    info = cached_pypi(dependency["name"], dependency["version"])
                    if info["status"] == "success":
                        dependency["latest_version"] = info["latest_version"]
                        dependency["state"] = info["state"]
                    else:
                        dependency["latest_version"] = None
                        dependency["state"] = "Unknown"
                        warnings.append(
                            f"PyPI lookup failed for {dependency['name']}: {info['error']}"
                        )

                progress.progress(index / len(dependencies))

            if use_enrichment and findings:
                status.write("Enriching findings with EPSS and CISA KEV...")
                findings, enrich_warnings = enrich_findings(
                    findings,
                    epss_lookup=cached_epss_lookup,
                    kev_lookup=cached_kev,
                )
                warnings.extend(enrich_warnings)

        findings = sort_findings(findings)
        risk_score = calculate_risk(findings)
        completed = len(scan_errors) == 0 and len(parser_errors) == 0

        st.session_state["scan_results"] = {
            "dependencies": dependencies,
            "findings": findings,
            "parser_errors": parser_errors,
            "scan_errors": scan_errors,
            "warnings": warnings,
            "risk_score": risk_score,
            "completed": completed,
            "enriched": use_enrichment,
        }
        status.success("Audit finished.")


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
if "scan_results" in st.session_state:
    results = st.session_state["scan_results"]
    dependencies = results["dependencies"]
    findings = results["findings"]
    parser_errors = results["parser_errors"]
    scan_errors = results["scan_errors"]
    warnings = results.get("warnings", [])
    risk_score = results["risk_score"]
    enriched = results.get("enriched", False)
    risk_level = get_risk_level(risk_score)

    st.divider()
    st.subheader("Security overview")

    urgent = sum(1 for item in findings if get_priority(item) == "Urgent")
    exploited = sum(1 for item in findings if item.get("known_exploited"))

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Dependencies", len(dependencies))
    c2.metric("Vulnerabilities", len(findings))
    c3.metric("Risk score", f"{risk_score}/100")
    c4.metric("Risk level", risk_level)
    c5.metric(
        "Urgent fixes",
        urgent if enriched else "n/a",
        help="Findings in the CISA KEV catalog or with EPSS >= 50%.",
    )

    if enriched and exploited:
        st.error(
            f"{exploited} finding(s) appear in the CISA Known Exploited "
            "Vulnerabilities catalog. Patch these first."
        )

    if findings:
        gauge_col, chart_col = st.columns([1, 1.2])

        with gauge_col:
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                number={"suffix": "/100", "font": {"color": "#e8f1ff"}},
                title={"text": f"{risk_level} risk", "font": {"color": "#9db2ce", "size": 16}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#64748b"},
                    "bar": {"color": RISK_COLORS.get(risk_level, "#3b82f6")},
                    "bgcolor": "#111c30",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 30], "color": "#14243a"},
                        {"range": [30, 60], "color": "#1a2c47"},
                        {"range": [60, 100], "color": "#21365a"},
                    ],
                },
            ))
            gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e8f1ff",
                height=280,
                margin=dict(l=20, r=20, t=50, b=10),
            )
            st.plotly_chart(gauge, width="stretch")

        with chart_col:
            severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
            counts = (
                pd.Series([item["severity"] for item in findings])
                .value_counts()
                .reindex(severity_order, fill_value=0)
            )
            chart_data = counts[counts > 0].rename_axis("Severity").reset_index(name="Count")
            fig = px.bar(
                chart_data,
                x="Severity",
                y="Count",
                color="Severity",
                text="Count",
                color_discrete_map=SEVERITY_COLORS,
                title="Findings by severity",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e8f1ff",
                showlegend=False,
                height=280,
                margin=dict(l=10, r=10, t=45, b=10),
            )
            fig.update_yaxes(showgrid=False, visible=False)
            st.plotly_chart(fig, width="stretch")

        st.caption(
            "Score = sum of severity weights x 10, capped at 100. "
            "Findings are sorted by remediation priority, then severity."
        )
    elif results["completed"]:
        st.success("No matching known vulnerabilities were returned for the dependencies checked.")
    else:
        st.warning(
            "No vulnerabilities were returned, but the audit is incomplete. "
            "Review verification errors before drawing conclusions."
        )

    for message in warnings:
        st.warning(message)

    tab_findings, tab_dependencies, tab_issues = st.tabs(
        ["Vulnerability findings", "Dependencies", "Audit issues"]
    )

    with tab_findings:
        if findings:
            rows = []
            for item in findings:
                row = {
                    "Priority": get_priority(item) if enriched else "n/a",
                    "Package": item["package"],
                    "Installed": item["installed_version"],
                    "Vulnerability": item["vulnerability_id"],
                    "Severity": item["severity"],
                    "Fixed in": item.get("fixed_version") or "Not supplied",
                }
                if enriched:
                    epss = item.get("epss")
                    row["Exploit probability (EPSS)"] = epss * 100 if epss is not None else None
                    row["CISA KEV"] = "Yes" if item.get("known_exploited") else "No"
                row["Summary"] = item["summary"]
                rows.append(row)

            column_config = {}
            if enriched:
                column_config["Exploit probability (EPSS)"] = st.column_config.ProgressColumn(
                    "Exploit probability (EPSS)",
                    format="%.1f%%",
                    min_value=0,
                    max_value=100,
                )
            st.dataframe(
                pd.DataFrame(rows),
                width="stretch",
                hide_index=True,
                column_config=column_config,
            )

            st.markdown("#### Details")
            for item in findings:
                label = f"{item['vulnerability_id']}  |  {item['package']}  |  {item['severity']}"
                with st.expander(label):
                    st.write(item["summary"])
                    if item.get("fixed_version"):
                        st.success(f"Upgrade to {item['fixed_version']} or later.")
                    if enriched and item.get("cve_ids"):
                        st.caption("CVE: " + ", ".join(item["cve_ids"]))
                    if item.get("references"):
                        st.markdown("**References**")
                        for url in item["references"][:5]:
                            st.markdown(f"- {url}")
        else:
            st.info("There are no vulnerability findings to display.")

    with tab_dependencies:
        if dependencies:
            dep_rows = []
            for item in dependencies:
                row = {
                    "Package": item["name"],
                    "Pinned version": item["version"],
                    "Ecosystem": item["ecosystem"],
                }
                if enriched:
                    row["Latest on PyPI"] = item.get("latest_version") or "Unknown"
                    row["Status"] = item.get("state", "Unknown")
                dep_rows.append(row)
            st.dataframe(pd.DataFrame(dep_rows), width="stretch", hide_index=True)
        else:
            st.info("No dependencies were successfully parsed.")

    with tab_issues:
        if scan_errors:
            st.subheader("Dependencies not verified")
            st.dataframe(pd.DataFrame(scan_errors), width="stretch", hide_index=True)
        if parser_errors:
            st.subheader("Manifest parsing issues")
            st.dataframe(pd.DataFrame(parser_errors), width="stretch", hide_index=True)
        if not scan_errors and not parser_errors:
            st.success("No scan or manifest parsing errors were reported.")

    report = generate_report(
        dependencies, findings, parser_errors + scan_errors, risk_score, warnings
    )
    st.download_button(
        "Download JSON audit report",
        data=report,
        file_name="supplyshield-audit-report.json",
        mime="application/json",
        type="primary",
    )

st.divider()
st.markdown(
    '<div class="small-note">SupplyShield AI is a prototype for known-vulnerability '
    "discovery. A clean scan does not prove a dependency is secure or detect every "
    "malicious package.</div>",
    unsafe_allow_html=True,
)
