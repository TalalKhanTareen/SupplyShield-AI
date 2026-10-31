# SupplyShield AI

SupplyShield AI is a Streamlit-based software supply-chain security prototype. It audits pinned Python dependencies against the OSV vulnerability database, classifies findings, calculates a cumulative risk score, and exports a JSON audit report.

## Features

- Upload or paste a Python `requirements.txt` manifest
- Parse exact package versions and flag unsupported manifest entries
- Query OSV for known vulnerabilities
- Extract severity and fixed-version information where supplied by OSV
- Calculate a cumulative risk score from returned findings
- View findings, dependencies, and audit issues in separate dashboard tabs
- Prioritise fixes as Urgent / Elevated / Standard using EPSS and CISA KEV
- Flag outdated and yanked package versions via PyPI
- Get recommended upgrades, a copy-paste `pip install` command, and a fixed `requirements.txt` download
- Filter findings, export CSV, and export a JSON security report
- Run automated risk-engine tests

## Free data sources (no API keys)

| Source | Used for |
| --- | --- |
| [OSV.dev](https://osv.dev) | Known vulnerabilities, severity, fixed versions |
| [PyPI JSON API](https://pypi.org) | Latest release and yanked-release detection |
| [FIRST EPSS](https://www.first.org/epss/) | Probability a CVE will be exploited |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs confirmed exploited in the wild |

Enrichment can be switched off from the sidebar. If an enrichment source is unreachable, the scan still completes and shows a warning.

## Technology

Python, Streamlit, Pandas, Plotly, Requests, Packaging, CVSS, and the OSV API.

## Run locally on Windows

Open PowerShell in the project folder.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`.

If PowerShell blocks virtual-environment activation, run this once in the same terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run tests

```powershell
python -m pytest -q
```

## Demo

The included `data/demo_requirements.txt` is preloaded in the dashboard. Press **Run Security Audit** to test the workflow. Internet access is required because vulnerability lookups are sent to OSV.

## Important limitations

This prototype identifies known vulnerabilities returned by OSV for the package versions queried. It does not prove that a package is safe, detect every malicious package, analyze every package ecosystem, or replace a professional security audit. A scan with verification or parsing errors is incomplete and must not be treated as a clean bill of health.
