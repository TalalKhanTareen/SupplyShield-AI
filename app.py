import streamlit as st

from scanner.dependency_parser import parse_requirements
from scanner.vulnerability_checker import check_vulnerability
from scanner.risk_engine import calculate_risk, get_risk_level
from scanner.report_generator import generate_report


st.set_page_config(
    page_title="SupplyShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SupplyShield AI")
st.subheader("Automated Software Supply Chain Security")

st.write(
    "Analyze Python dependencies for known vulnerabilities, "
    "prioritize findings, and generate a security report."
)

uploaded_file = st.file_uploader(
    "Upload requirements.txt",
    type=["txt"]
)

if uploaded_file is not None:
    content = uploaded_file.getvalue().decode(
        "utf-8",
        errors="replace"
    )

    if st.button("Scan Project", type="primary"):
        dependencies, parser_errors = parse_requirements(content)

        findings = []
        scan_errors = []

        progress = st.progress(0)
        status = st.empty()

        total = len(dependencies)

        for index, dependency in enumerate(dependencies, start=1):
            status.write(
                f"Checking {dependency['name']} "
                f"{dependency['version']}..."
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

            progress.progress(index / total if total else 1)

        risk_score = calculate_risk(findings)

        st.session_state["scan_results"] = {
            "dependencies": dependencies,
            "findings": findings,
            "parser_errors": parser_errors,
            "scan_errors": scan_errors,
            "risk_score": risk_score
        }

        status.write("Scan completed.")

if "scan_results" in st.session_state:
    results = st.session_state["scan_results"]

    dependencies = results["dependencies"]
    findings = results["findings"]
    parser_errors = results["parser_errors"]
    scan_errors = results["scan_errors"]
    risk_score = results["risk_score"]

    st.divider()
    st.header("Security Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Dependencies", len(dependencies))
    col2.metric("Known Vulnerabilities", len(findings))
    col3.metric("Risk Score", f"{risk_score}/100")

    st.write(f"Risk Level: **{get_risk_level(risk_score)}**")

    if findings:
        st.subheader("Vulnerability Findings")
        st.dataframe(findings, use_container_width=True)
    else:
        st.info(
            "No matching known vulnerabilities were returned "
            "for the successfully checked dependencies."
        )

    if scan_errors:
        st.subheader("Dependencies Not Verified")
        st.dataframe(scan_errors, use_container_width=True)

    if parser_errors:
        st.subheader("Manifest Parsing Issues")
        st.dataframe(parser_errors, use_container_width=True)

    report = generate_report(
        dependencies,
        findings,
        parser_errors + scan_errors,
        risk_score
    )

    st.download_button(
        "Download Security Report",
        data=report,
        file_name="supplyshield-report.json",
        mime="application/json"
    )

    if scan_errors or parser_errors:
        st.warning(
            "The scan is incomplete. Review the errors before "
            "drawing conclusions about project security."
        )
    else:
        st.success("All parsed dependencies were checked successfully.")
