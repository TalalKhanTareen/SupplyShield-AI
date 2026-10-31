# SupplyShield AI

SupplyShield AI is an automated software supply chain security
prototype that analyzes Python dependencies for known vulnerabilities.

## Features

- Python requirements.txt parsing
- Known vulnerability lookup through the OSV API
- Dependency risk scoring
- Security findings dashboard
- JSON report generation
- Dependency verification error reporting

## Technology Stack

- Python
- Streamlit
- Requests
- Packaging
- OSV API
- GitHub

## Project Structure

- app.py: Main dashboard
- scanner/dependency_parser.py: Dependency parsing
- scanner/vulnerability_checker.py: Vulnerability lookup
- scanner/risk_engine.py: Risk scoring
- scanner/report_generator.py: JSON reports
- tests/test_risk_engine.py: Risk engine tests

## Run Locally

Install the dependencies:

    pip install -r requirements.txt

Start the application:

    streamlit run app.py

Upload a Python requirements.txt file and start the scan.

## Limitations

The prototype checks for known vulnerabilities in supported
package versions. It does not prove that a package is safe,
detect every malicious package, or replace a complete security audit.

Network failures and unsupported manifest entries must be reviewed
before considering a scan complete.

## Future Improvements

- Fixed-version remediation recommendations
- More package ecosystems
- GitHub Actions integration
- AI-assisted vulnerability explanations
- Software Bill of Materials generation
- Pull request security reporting
