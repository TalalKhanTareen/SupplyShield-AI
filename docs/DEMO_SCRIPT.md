# SupplyShield AI — 3-minute demo script

## 0:00–0:25 — Problem

"Modern applications depend on third-party packages. A vulnerable dependency can introduce risk, and teams need a quick way to identify what to investigate first."

## 0:25–0:50 — Product

"SupplyShield AI audits pinned Python dependencies. It combines OSV vulnerability records with optional PyPI, FIRST EPSS, and CISA KEV enrichment. It uses public data sources and requires no API keys."

## 0:50–1:25 — Run the audit

Open the app and use the preloaded demo manifest. Click **Run security audit**. Point out the progress indicator, dependency count, findings, risk score, and verdict.

## 1:25–2:00 — Explain prioritisation

Open the findings tab. Explain that related advisories are deduplicated, severity contributes to the risk score, and EPSS/KEV data helps prioritise findings when enrichment is available. Show a finding's references and fixed-version information.

## 2:00–2:35 — Remediate

Open **Recommended fixes**. Show the target version, copy-paste install command, and generated fixed requirements file. Explain that recommended changes still need compatibility testing.

## 2:35–3:00 — Evidence and limitations

Download the CSV and JSON audit report. Close with: "The tool identifies known issues returned by connected public data sources. An incomplete lookup is not a clean result, and a clean scan is not proof that software is secure."

## Backup plan

If the internet or a public API is unavailable, show the interface and explain how failed lookups appear under **Audit issues**. Never present missing data as a successful security check.
