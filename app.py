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
from scanner.remediation import build_fixed_requirements, suggest_upgrades
from scanner.report_generator import generate_report
from scanner.risk_engine import calculate_risk, deduplicate_findings, get_priority, get_risk_level, sort_findings
from scanner.vulnerability_checker import check_vulnerability


BASE_DIR = Path(__file__).resolve().parent
DEMO_FILE = BASE_DIR / "data" / "demo_requirements.txt"
REPO_URL = "https://github.com/TalalKhanTareen/SupplyShield-AI"

SEVERITY_COLORS = {"Critical":"#dc2626","High":"#ea580c","Medium":"#d99a1e","Low":"#0284c7","Unknown":"#64748b"}
SEVERITY_TEXT_COLORS = {"Critical":"#b91c1c","High":"#c2410c","Medium":"#946200","Low":"#0369a1","Unknown":"#475569"}
SEVERITY_BACKGROUND_COLORS = {"Critical":"#fee2e2","High":"#ffedd5","Medium":"#fef3c7","Low":"#e0f2fe","Unknown":"#f1f5f9"}
PRIORITY_COLORS = {"Urgent":"#dc2626","Elevated":"#ea580c","Standard":"#1f7a4d"}
PRIORITY_TEXT_COLORS = {"Urgent":"#b91c1c","Elevated":"#c2410c","Standard":"#166534"}
PRIORITY_BACKGROUND_COLORS = {"Urgent":"#fee2e2","Elevated":"#ffedd5","Standard":"#dcfce7"}
RISK_COLORS = {"Critical":"#dc2626","High":"#ea580c","Medium":"#d99a1e","Low":"#0284c7","No known findings":"#1f9d63"}
RISK_TEXT_COLORS = {"Critical":"#b91c1c","High":"#c2410c","Medium":"#946200","Low":"#0369a1","No known findings":"#166534"}
st.set_page_config(
    page_title="SupplyShield AI | Dependency Security Audit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

STYLE_FILE = BASE_DIR / "assets" / "supplyshield.css"
if STYLE_FILE.exists():
    st.markdown(
        f"<style>{STYLE_FILE.read_text(encoding='utf-8')}</style>",
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


def style_table(frame):
    """Apply readable severity and priority badges in the findings table."""
    styled = frame.style
    if "Severity" in frame.columns:
        styled = styled.map(
            lambda value: (
                f"color: {SEVERITY_TEXT_COLORS.get(value, '#475569')}; "
                f"background-color: {SEVERITY_BACKGROUND_COLORS.get(value, '#f1f5f9')}; "
                "font-weight: 700"
            ),
            subset=["Severity"],
        )
    if "Priority" in frame.columns:
        styled = styled.map(
            lambda value: (
                f"color: {PRIORITY_TEXT_COLORS.get(value, '#475569')}; "
                f"background-color: {PRIORITY_BACKGROUND_COLORS.get(value, '#f1f5f9')}; "
                "font-weight: 700"
            ),
            subset=["Priority"],
        )
    return styled


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
    state = "on" if use_enrichment else "off"
    st.markdown(
        '<span class="pill on">OSV.dev</span>'
        f'<span class="pill {state}">PyPI</span>'
        f'<span class="pill {state}">FIRST EPSS</span>'
        f'<span class="pill {state}">CISA KEV</span>',
        unsafe_allow_html=True,
    )
    st.caption("Ecosystem: Python / PyPI")

    st.divider()
    st.markdown("### Risk levels")
    st.caption("Critical 80+  |  High 60+  |  Medium 30+  |  Low 1+")
    st.markdown(f"[View source on GitHub]({REPO_URL})")


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Dependency security audit</div>
      <h1>Know what is risky in your<br>Python dependencies.</h1>
      <p>Upload a <code>requirements.txt</code> and get a prioritised list of known
      vulnerabilities, backed by live exploit data, with the exact upgrades to fix them.</p>
      <div class="chips">
        <span class="pill">No sign-up</span>
        <span class="pill">No API keys</span>
        <span class="pill">Free public data sources</span>
        <span class="pill">Exportable report</span>
      </div>
      <div class="feature-strip">
        <span class="feature-chip">◈ Risk-based prioritisation</span>
        <span class="feature-chip">↗ Upgrade recommendations</span>
        <span class="feature-chip">✓ Audit-ready exports</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

default_manifest = DEMO_FILE.read_text(encoding="utf-8") if DEMO_FILE.exists() else ""

# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #
st.markdown("#### 1. Provide your dependencies")
input_tab, paste_tab = st.tabs(["Upload a file", "Paste text or use the demo"])
with input_tab:
    uploaded_file = st.file_uploader(
        "Upload a requirements.txt file",
        type=["txt"],
        help="Use exact package pins such as requests==2.31.0.",
        label_visibility="collapsed",
    )
with paste_tab:
    pasted_manifest = st.text_area(
        "requirements.txt content",
        value=default_manifest,
        height=150,
        help="The demo manifest is preloaded so you can try the tool immediately.",
    )

manifest = (
    uploaded_file.getvalue().decode("utf-8", errors="replace")
    if uploaded_file is not None
    else pasted_manifest
)

st.markdown("#### 2. Run the audit")
scan_col, hint_col = st.columns([1, 3])
with scan_col:
    scan_clicked = st.button("Run security audit", type="primary", width="stretch")
with hint_col:
    st.caption(
        "Only exact pins (package==1.2.3) can be checked. "
        "Your manifest is sent only to the public APIs listed in the sidebar."
    )


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

        findings = deduplicate_findings(findings)
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
        history = st.session_state.setdefault("scan_history", [])
        history.insert(0, {
            "time": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
            "packages": len(dependencies),
            "findings": len(findings),
            "risk": risk_score,
            "status": "Complete" if completed else "Partial",
        })
        st.session_state["scan_history"] = history[:5]
        status.empty()
        progress.empty()


# --------------------------------------------------------------------------- #
# Empty state: explain the product before the first scan
# --------------------------------------------------------------------------- #
if "scan_results" not in st.session_state:
    st.markdown("#### How it works")
    a, b, c = st.columns(3)
    a.markdown(
        '<div class="card"><div class="num">STEP 1</div><h4>Check for known flaws</h4>'
        "<p>Every pinned package is looked up in the OSV vulnerability database "
        "for known security issues.</p></div>",
        unsafe_allow_html=True,
    )
    b.markdown(
        '<div class="card"><div class="num">STEP 2</div><h4>Prioritise with real data</h4>'
        "<p>Findings are ranked using EPSS exploit probability and the CISA list "
        "of vulnerabilities exploited in the wild.</p></div>",
        unsafe_allow_html=True,
    )
    c.markdown(
        '<div class="card"><div class="num">STEP 3</div><h4>Fix with confidence</h4>'
        "<p>Get the exact upgrade for each package, plus a ready-to-use "
        "requirements file and a JSON report.</p></div>",
        unsafe_allow_html=True,
    )


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
    level_color = RISK_COLORS.get(risk_level, "#1f7a4d")
    level_text_color = RISK_TEXT_COLORS.get(risk_level, "#14532d")

    st.divider()
    st.markdown("#### Results")

    # ---- Plain-English verdict ------------------------------------------- #
    vulnerable_pkgs = len({item["package"].lower() for item in findings})
    urgent = sum(1 for item in findings if get_priority(item) == "Urgent")
    exploited = sum(1 for item in findings if item.get("known_exploited"))
    upgrades = suggest_upgrades(dependencies, findings)

    if findings:
        headline = (
            f"{len(findings)} known vulnerabilit{'y' if len(findings) == 1 else 'ies'} "
            f"in {vulnerable_pkgs} of {len(dependencies)} packages"
        )
        detail = (
            f"Overall risk is <b>{risk_level}</b> ({risk_score}/100). "
            + (f"<b>{urgent}</b> need urgent attention. " if enriched and urgent else "")
            + (f"{len(upgrades)} package upgrade(s) are recommended below." if upgrades else "")
        )
        label = "Action needed"
    elif results["completed"]:
        headline = "No known vulnerabilities found"
        detail = "All dependencies were checked and none matched a known vulnerability."
        label = "Looks good"
        level_color = RISK_COLORS["No known findings"]
        level_text_color = RISK_TEXT_COLORS["No known findings"]
    else:
        headline = "Audit incomplete"
        detail = "Some dependencies could not be verified. Review the Audit issues tab before drawing conclusions."
        label = "Needs review"
        level_color = RISK_COLORS["Medium"]
        level_text_color = RISK_TEXT_COLORS["Medium"]

    st.markdown(
        f'<div class="verdict" style="border-left-color:{level_color}">'
        f'<div class="label" style="color:{level_text_color}">{label}</div>'
        f'<div class="headline">{headline}</div>'
        f'<div class="detail">{detail}</div></div>',
        unsafe_allow_html=True,
    )

    if enriched and exploited:
        st.error(
            f"{exploited} finding(s) appear in the CISA Known Exploited "
            "Vulnerabilities catalog, so attackers are already using them. Patch these first."
        )

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

    # A simple, explainable posture grade based on this scan's risk score.
    if not results["completed"]:
        grade, grade_text, grade_color = "—", "Incomplete scan: resolve audit issues before interpreting this grade.", "#64748b"
    elif risk_score >= 80:
        grade, grade_text, grade_color = "F", "Critical exposure: address the highest-priority findings immediately.", "#b91c1c"
    elif risk_score >= 60:
        grade, grade_text, grade_color = "D", "High exposure: prioritise upgrades and validate the fixes with tests.", "#c2410c"
    elif risk_score >= 30:
        grade, grade_text, grade_color = "C", "Moderate exposure: review recommended upgrades and reduce residual risk.", "#946200"
    elif risk_score > 0:
        grade, grade_text, grade_color = "B", "Lower observed exposure: resolve remaining findings and keep dependencies current.", "#0369a1"
    else:
        grade, grade_text, grade_color = "A", "No known findings returned for the dependencies checked.", "#166534"

    st.markdown(
        f'<div class="grade-card"><div class="grade-letter" style="color:{grade_color}">{grade}</div>'
        f'<div class="grade-copy"><div class="section-kicker">Security posture grade</div>'
        f'<strong>{grade_text}</strong><p>This grade reflects the scan result only; it is not a certification '
        'and does not prove the application is secure.</p></div></div>',
        unsafe_allow_html=True,
    )

    if findings:
        gauge_col, chart_col = st.columns([1, 1.2])

        with gauge_col:
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                number={"suffix": "/100", "font": {"color": "#1f2937"}},
                title={"text": "Risk score", "font": {"color": "#14532d", "size": 15}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#64748b"},
                    "bar": {"color": level_color},
                    "bgcolor": "#f3f8f4",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 30], "color": "#e8f5eb"},
                        {"range": [30, 60], "color": "#fef3c7"},
                        {"range": [60, 100], "color": "#fee2e2"},
                    ],
                },
            ))
            gauge.update_layout(
                paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", font_color="#1f2937",
                height=260, margin=dict(l=20, r=20, t=50, b=10),
            )
            st.plotly_chart(gauge, width="stretch")

        with chart_col:
            order = ["Critical", "High", "Medium", "Low", "Unknown"]
            counts = (
                pd.Series([item["severity"] for item in findings])
                .value_counts()
                .reindex(order, fill_value=0)
            )
            chart_data = counts[counts > 0].rename_axis("Severity").reset_index(name="Count")
            fig = px.bar(
                chart_data, x="Severity", y="Count", color="Severity", text="Count",
                color_discrete_map=SEVERITY_COLORS, title="Findings by severity",
            )
            fig.update_layout(
                paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                font_color="#1f2937", showlegend=False,
                height=260, margin=dict(l=10, r=10, t=45, b=10),
            )
            fig.update_yaxes(showgrid=True, gridcolor="#e7eee8", zeroline=False, color="#475569", title=None)
            st.plotly_chart(fig, width="stretch")

        st.caption(
            "Risk score combines the highest severity with a small increase for each additional "
            "distinct finding. Related OSV advisories are merged when their identifiers overlap. "
            "Findings are sorted by exploit priority, then severity."
        )

    for message in warnings:
        st.warning(message)

    tab_fix, tab_findings, tab_dependencies, tab_issues = st.tabs(
        ["Recommended fixes", "Vulnerability findings", "Dependencies", "Audit issues"]
    )

    # ---- Recommended fixes ------------------------------------------------ #
    with tab_fix:
        if upgrades:
            st.write("Upgrade these packages to the newest fixed version reported across the findings:")
            st.dataframe(
                pd.DataFrame(upgrades).rename(columns={
                    "package": "Package", "current": "Current", "target": "Upgrade to"
                }),
                width="stretch",
                hide_index=True,
            )
            st.markdown("**Copy and run**")
            st.code(
                "pip install " + " ".join(f"{u['package']}=={u['target']}" for u in upgrades),
                language="bash",
            )
            st.download_button(
                "Download upgraded requirements.txt",
                data=build_fixed_requirements(dependencies, upgrades),
                file_name="requirements.fixed.txt",
                mime="text/plain",
            )
            st.caption(
                "Always run your tests after upgrading. Some upgrades cross major versions "
                "and can include breaking changes."
            )
        elif findings:
            st.info(
                "No safe upgrade target was reported for these findings. "
                "Check the references in the findings tab for mitigations."
            )
        else:
            st.success("Nothing to fix. No known vulnerabilities were found.")

    # ---- Findings --------------------------------------------------------- #
    with tab_findings:
        if findings:
            severities = sorted({f["severity"] for f in findings}, key=lambda s: list(SEVERITY_COLORS).index(s))
            f1, f2 = st.columns([2, 1])
            chosen = f1.multiselect("Filter by severity", severities, default=severities)
            query = f2.text_input("Search package or ID", placeholder="e.g. flask")
            visible = [
                f for f in findings
                if f["severity"] in chosen
                and (not query or query.lower() in f["package"].lower()
                     or query.lower() in f["vulnerability_id"].lower())
            ]

            rows = []
            for item in visible:
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
                    if epss is not None:
                        try:
                            epss = float(epss)
                            epss = epss / 100 if epss > 1 else epss
                        except (TypeError, ValueError):
                            epss = None
                    row["Exploit probability (EPSS)"] = epss * 100 if epss is not None else None
                    row["CISA KEV"] = "Yes" if item.get("known_exploited") else "No"
                row["Summary"] = item["summary"]
                rows.append(row)

            if rows:
                frame = pd.DataFrame(rows)
                column_config = {}
                if enriched:
                    column_config["Exploit probability (EPSS)"] = st.column_config.ProgressColumn(
                        "Exploit probability (EPSS)", format="%.1f%%", min_value=0, max_value=100,
                    )
                st.dataframe(
                    style_table(frame), width="stretch", hide_index=True,
                    column_config=column_config,
                )
                st.download_button(
                    "Download findings as CSV",
                    data=frame.to_csv(index=False),
                    file_name="supplyshield-findings.csv",
                    mime="text/csv",
                )

                st.markdown("#### Details")
                for item in visible:
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
                st.info("No findings match the current filter.")
        else:
            st.info("There are no vulnerability findings to display.")

    # ---- Dependencies ----------------------------------------------------- #
    with tab_dependencies:
        if dependencies:
            vulnerable = {item["package"].lower() for item in findings}
            dep_rows = []
            for item in dependencies:
                row = {
                    "Package": item["name"],
                    "Pinned version": item["version"],
                    "Ecosystem": item["ecosystem"],
                    "Vulnerable": "Yes" if item["name"].lower() in vulnerable else "No",
                }
                if enriched:
                    row["Latest on PyPI"] = item.get("latest_version") or "Unknown"
                    row["Status"] = item.get("state", "Unknown")
                dep_rows.append(row)
            st.dataframe(pd.DataFrame(dep_rows), width="stretch", hide_index=True)
        else:
            st.info("No dependencies were successfully parsed.")

    # ---- Issues ----------------------------------------------------------- #
    with tab_issues:
        if scan_errors:
            st.subheader("Dependencies not verified")
            st.dataframe(pd.DataFrame(scan_errors), width="stretch", hide_index=True)
        if parser_errors:
            st.subheader("Manifest parsing issues")
            st.dataframe(pd.DataFrame(parser_errors), width="stretch", hide_index=True)
        if not scan_errors and not parser_errors:
            st.success("No scan or manifest parsing errors were reported.")

    st.download_button(
        "Download full JSON audit report",
        data=generate_report(
            dependencies, findings, parser_errors + scan_errors, risk_score, warnings
        ),
        file_name="supplyshield-audit-report.json",
        mime="application/json",
        type="primary",
    )

if st.session_state.get("scan_history"):
    with st.expander("Recent scans in this session", expanded=False):
        st.caption("History is kept only in this browser session and is cleared when the session resets.")
        st.dataframe(
            pd.DataFrame(st.session_state["scan_history"]).rename(columns={
                "time": "Time", "packages": "Packages", "findings": "Findings",
                "risk": "Risk score", "status": "Status",
            }),
            width="stretch",
            hide_index=True,
        )

st.divider()
st.markdown(
    '<div class="small-note">Data from '
    '<a href="https://osv.dev">OSV.dev</a>, <a href="https://pypi.org">PyPI</a>, '
    '<a href="https://www.first.org/epss/">FIRST EPSS</a> and '
    '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>. '
    "SupplyShield AI is a prototype for known-vulnerability discovery. A clean scan does not "
    "prove a dependency is secure or detect every malicious package.</div>",
    unsafe_allow_html=True,
)
