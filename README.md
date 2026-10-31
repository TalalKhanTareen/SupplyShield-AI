# SupplyShield AI

**Automated Software Supply-Chain Security Auditing**

SupplyShield AI is a Python dependency-auditing dashboard built with Streamlit. It checks pinned dependencies for publicly reported vulnerabilities, enriches findings with exploit intelligence, ranks remediation priorities, and produces downloadable audit artifacts.

> **Project status:** Hackathon / educational prototype. It helps discover known vulnerabilities; it is not a guarantee that software or dependencies are safe.

## Highlights

- Upload, paste, or start with the included demo `requirements.txt`.
- Parse exact package pins and report unsupported or unverified manifest lines.
- Query the [OSV.dev](https://osv.dev) vulnerability database.
- Enrich CVE findings with [FIRST EPSS](https://www.first.org/epss/) exploit-probability data and the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Check PyPI for current package versions and yanked releases.
- Deduplicate related advisories and calculate an explainable risk score.
- Prioritise fixes, recommend fixed versions where available, and generate a revised requirements file.
- Explore findings, severity charts, package status, and scan issues in a dashboard.
- Export findings to CSV and the complete audit to JSON.
- Run automated tests and continuous integration with GitHub Actions.

## Architecture

```text
app.py
  ├── scanner/dependency_parser.py     Parse and validate dependency pins
  ├── scanner/vulnerability_checker.py Query OSV for known vulnerabilities
  ├── scanner/enrichment.py            PyPI, FIRST EPSS and CISA KEV lookups
  ├── scanner/risk_engine.py           Deduplication, risk and priority
  ├── scanner/remediation.py            Upgrade suggestions and fixed manifest
  └── scanner/report_generator.py      JSON audit report
```

## Data sources

| Source | Purpose | API key |
|---|---|---|
| [OSV.dev](https://osv.dev) | Vulnerability records and fixed-version ranges | Not required |
| [PyPI JSON API](https://pypi.org) | Latest package release and yanked-release status | Not required |
| [FIRST EPSS](https://www.first.org/epss/) | Estimated probability of CVE exploitation | Not required |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities known to be exploited in the wild | Not required |

The dashboard uses public services over HTTPS. Enrichment can be disabled in the sidebar. If a data source is unavailable, the app reports warnings or failed checks rather than silently treating unavailable data as safe.

## Run locally

Python 3.11 or newer is recommended.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local address printed by Streamlit (normally `http://localhost:8501`). An internet connection is required for live vulnerability and enrichment lookups.

## Try the demo

1. Start the app.
2. Open **Paste text or use the demo**; the sample manifest is preloaded.
3. Select **Run security audit**.
4. Review the verdict, score, severity distribution, and recommended fixes.
5. Explore the findings, dependencies, and audit-issues tabs.
6. Download the CSV findings or JSON audit report.

The demo intentionally uses older pinned packages to exercise the vulnerability workflow. Do not use its dependencies for a production application.

## Tests and quality checks

Install dependencies, then run:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

The offline tests cover dependency parsing, mocked OSV responses, threat-intelligence enrichment, risk scoring and prioritisation, remediation suggestions, and JSON report generation. GitHub Actions runs the automated test suite on pushes and pull requests.

## Repository structure

```text
.
├── app.py
├── assets/
│   └── supplyshield.css
├── data/
│   └── demo_requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── dependency_parser.py
│   ├── enrichment.py
│   ├── remediation.py
│   ├── report_generator.py
│   ├── risk_engine.py
│   └── vulnerability_checker.py
├── tests/
│   ├── test_dependency_parser.py
│   ├── test_enrichment.py
│   ├── test_remediation.py
│   ├── test_report_generator.py
│   ├── test_risk_engine.py
│   └── test_vulnerability_checker.py
├── .github/
│   └── workflows/
│       └── tests.yml
├── .streamlit/
│   └── config.toml
├── docs/
│   ├── DEMO_SCRIPT.md
│   └── PROJECT_SUBMISSION_CHECKLIST.md
├── CONTRIBUTING.md
├── SECURITY.md
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Limitations and responsible use

- Results depend on the records returned by external data providers at scan time.
- A clean result means no matching known vulnerability was returned for the checked versions; it does not prove a package is secure.
- Only supported, exactly pinned Python dependencies are assessed. Nested requirements, editable installs, direct URLs, and unsupported version constraints are reported as issues rather than assumed safe.
- A failed lookup means the dependency was **not verified**. Review all audit issues before relying on the result.
- EPSS is a probability estimate, not proof of exploitation. CISA KEV indicates that a CVE is known to be exploited.
- Upgrade suggestions are based on fixed versions reported by OSV and must be reviewed and tested before deployment.
- Do not upload secrets, credentials, private indexes, or sensitive manifest comments. Package names and versions are sent to the public data services used by the scanner.
- This project is a decision-support tool and does not replace dependency review, software composition analysis, testing, or a professional security assessment.

## Presentation

For a short hackathon demo, show the included manifest, run the audit, explain why findings are ranked, demonstrate one recommended upgrade, then export the CSV and JSON report. Clearly state the prototype's limitations.

## Maintainer

Created as a student hackathon project. Contributions, bug reports, and improvement suggestions are welcome.
