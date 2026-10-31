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
from scanner.risk_engine import calculate_risk, get_priority, get_risk_level, sort_findings
from scanner.vulnerability_checker import check_vulnerability


BASE_DIR = Path(__file__).resolve().parent
DEMO_FILE = BASE_DIR / "data" / "demo_requirements.txt"
REPO_URL = "https://github.com/TalalKhanTareen/SupplyShield-AI"

# Matte palette: forest green + camel, with muted (non-neon) status colours
SEVERITY_COLORS = {
    "Critical": "#c4574a",  # brick
    "High": "#d08a4a",      # burnt camel
    "Medium": "#d4b45f",    # mustard
    "Low": "#8aa6a3",       # muted sage-teal
    "Unknown": "#8a8f86",   # stone
}
PRIORITY_COLORS = {"Urgent": "#c4574a", "Elevated": "#d08a4a", "Standard": "#a9a590"}
RISK_COLORS = {
    "Critical": "#c4574a",
    "High": "#d08a4a",
    "Medium": "#d4b45f",
    "Low": "#8aa6a3",
    "No known findings": "#6b9a78",  # matte green
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
    :root {
        --bg: #14201a; --surface: #1c2b23; --surface-2: #223329;
        --border: #33493c; --green: #6b9a78; --green-dark: #4f7a5c;
        --camel: #c19a6b; --camel-light: #d2ae7e;
        --text: #f1ede4; --muted: #b9b3a3;
    }
    #MainMenu, footer { visibility: hidden; }
    .block-container { padding-top: 1.6rem; max-width: 1200px; }

    /* ---------- hero ---------- */
    .hero {
        background: radial-gradient(circle at 88% 0%, #3f5f4a 0%, #223529 42%, #14201a 100%);
        border: 1px solid var(--border); border-radius: 18px;
        border-bottom: 3px solid var(--camel);
        padding: 34px 36px; margin-bottom: 1.2rem;
    }
    .hero .eyebrow { color: var(--camel); font-weight: 700; letter-spacing: .12em;
                     font-size: .78rem; text-transform: uppercase; }
    .hero h1 { margin: 6px 0 8px 0; font-size: 2.5rem; font-weight: 800; color: #f6f2e9; line-height: 1.1; }
    .hero p  { margin: 0; color: #c4bdad; font-size: 1.05rem; max-width: 720px; }
    .hero code { background: #2a3d31; color: var(--camel-light); padding: 1px 6px; border-radius: 5px; }
    .hero .chips { margin-top: 18px; }

    /* ---------- pills ---------- */
    .pill { display: inline-block; padding: 3px 11px; margin: 0 6px 6px 0;
            border-radius: 999px; font-size: .76rem; font-weight: 600;
            border: 1px solid #3d5547; color: #cfc8b8; background: #22332a;
            transition: all .2s ease; }
    .hero .pill:hover { border-color: var(--camel); color: var(--camel-light); transform: translateY(-1px); }
    .pill.on  { border-color: var(--green-dark); color: #9fcbab; background: #1d3326; }
    .pill.off { border-color: #4b524a; color: #8a8f86; }

    /* ---------- cards / metrics with hover ---------- */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
            padding: 20px 22px; height: 100%;
            transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease; }
    .card:hover { transform: translateY(-4px); border-color: var(--camel);
                  box-shadow: 0 10px 24px rgba(0,0,0,.28); }
    .card .num { color: var(--camel); font-weight: 800; font-size: .85rem; letter-spacing: .08em; }
    .card h4 { margin: 4px 0 6px 0; color: #f6f2e9; font-size: 1.08rem; }
    .card p  { margin: 0; color: var(--muted); font-size: .93rem; line-height: 1.5; }

    div[data-testid="stMetric"] { background: var(--surface); border: 1px solid var(--border);
                                  padding: 14px 18px; border-radius: 12px;
                                  transition: transform .2s ease, border-color .2s ease; }
    div[data-testid="stMetric"]:hover { transform: translateY(-2px); border-color: var(--green); }
    div[data-testid="stMetricLabel"] { color: var(--muted); }

    /* ---------- verdict banner ---------- */
    .verdict { border-radius: 14px; padding: 18px 22px; margin: .4rem 0 1rem 0;
               border: 1px solid var(--border); border-left-width: 6px; background: var(--surface); }
    .verdict .label { font-size: .78rem; font-weight: 700; letter-spacing: .1em;
                      text-transform: uppercase; opacity: .95; }
    .verdict .headline { font-size: 1.35rem; font-weight: 700; color: #f6f2e9; margin: 2px 0 4px 0; }
    .verdict .detail { color: #c4bdad; font-size: .97rem; }

    /* ---------- buttons ---------- */
    [data-testid="stBaseButton-primary"] {
        background: var(--green-dark); border: 1px solid var(--green); color: #f6f2e9;
        font-weight: 700; border-radius: 10px;
        transition: background .2s ease, transform .15s ease, box-shadow .2s ease;
    }
    [data-testid="stBaseButton-primary"]:hover {
        background: var(--camel); border-color: var(--camel-light); color: #1a1a14;
        transform: translateY(-1px); box-shadow: 0 6px 16px rgba(193,154,107,.28);
    }
    [data-testid="stBaseButton-secondary"] {
        border: 1px solid var(--camel); color: var(--camel-light); border-radius: 10px;
        background: transparent; transition: background .2s ease, transform .15s ease;
    }
    [data-testid="stBaseButton-secondary"]:hover {
        background: rgba(193,154,107,.14); border-color: var(--camel-light);
        color: var(--camel-light); transform: translateY(-1px);
    }

    /* ---------- tabs ---------- */
    button[data-baseweb="tab"] { font-weight: 600; transition: color .2s ease; }
    button[data-baseweb="tab"]:hover { color: var(--camel-light); }
    button[data-baseweb="tab"][aria-selected="true"] { color: var(--camel-light); }
    div[data-baseweb="tab-highlight"] { background-color: var(--camel); }

    /* ---------- expanders & inputs ---------- */
    details { border: 1px solid var(--border) !important; border-radius: 10px !important;
              transition: border-color .2s ease; }
    details:hover { border-color: var(--green) !important; }
    [data-testid="stFileUploaderDropzone"] { border: 1.5px dashed var(--camel);
                                             background: var(--surface); border-radius: 12px;
                                             transition: background .2s ease; }
    [data-testid="stFileUploaderDropzone"]:hover { background: var(--surface-2); }

    .small-note { color: #9a9484; font-size: .82rem; }
    .small-note a { color: var(--camel-light); }
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


def style_table(frame):
    """Colour-code severity and priority cells."""
    styled = frame.style
    if "Severity" in frame.columns:
        styled = styled.map(
            lambda v: f"color: {SEVERITY_COLORS.get(v, '#f1ede4')}; font-weight: 700",
            subset=["Severity"],
        )
    if "Priority" in frame.columns:
        styled = styled.map(
            lambda v: f"color: {PRIORITY_COLORS.get(v, '#f1ede4')}; font-weight: 700",
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
    level_color = RISK_COLORS.get(risk_level, "#c19a6b")

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
    else:
        headline = "Audit incomplete"
        detail = "Some dependencies could not be verified. Review the Audit issues tab before drawing conclusions."
        label = "Needs review"
        level_color = RISK_COLORS["Medium"]

    st.markdown(
        f'<div class="verdict" style="border-left-color:{level_color}">'
        f'<div class="label" style="color:{level_color}">{label}</div>'
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

    if findings:
        gauge_col, chart_col = st.columns([1, 1.2])

        with gauge_col:
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                number={"suffix": "/100", "font": {"color": "#f1ede4"}},
                title={"text": "Risk score", "font": {"color": "#b9b3a3", "size": 15}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#8a8f86"},
                    "bar": {"color": level_color},
                    "bgcolor": "#1c2b23",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 30], "color": "#223329"},
                        {"range": [30, 60], "color": "#2a3d31"},
                        {"range": [60, 100], "color": "#33493c"},
                    ],
                },
            ))
            gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", font_color="#f1ede4",
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
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#f1ede4", showlegend=False,
                height=260, margin=dict(l=10, r=10, t=45, b=10),
            )
            fig.update_yaxes(showgrid=False, visible=False)
            st.plotly_chart(fig, width="stretch")

        st.caption(
            "Score = sum of severity weights x 10, capped at 100. "
            "Findings are sorted by remediation priority, then severity."
        )

    for message in warnings:
        st.warning(message)

    tab_fix, tab_findings, tab_dependencies, tab_issues = st.tabs(
        ["Recommended fixes", "Vulnerability findings", "Dependencies", "Audit issues"]
    )

    # ---- Recommended fixes ------------------------------------------------ #
    with tab_fix:
        if upgrades:
            st.write("Upgrade these packages to the lowest version that resolves every reported issue:")
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
