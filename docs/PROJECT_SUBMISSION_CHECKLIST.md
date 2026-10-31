# Submission readiness checklist

Use this list before submitting SupplyShield AI to a hackathon, course evaluator, or portfolio.

## Project quality

- [ ] Open the app locally with `streamlit run app.py`.
- [ ] Confirm the white-and-emerald theme and text contrast at desktop and mobile widths.
- [ ] Run the demo manifest and verify the results tabs render.
- [ ] Test a manifest containing one pinned package and one unsupported line.
- [ ] Check that API failures appear as warnings or audit issues, not as a clean scan.
- [ ] Verify recommended-upgrade output when a fixed version is available.
- [ ] Download and open the CSV and JSON reports.
- [ ] Run `pip install -r requirements-dev.txt` and `python -m pytest -q`.
- [ ] Confirm the GitHub Actions workflow completes successfully after the latest push.

## Deployment

- [ ] Confirm the Streamlit Community Cloud app is connected to this repository, branch `main`, entry file `app.py`.
- [ ] Wait for the latest commit to deploy and open the real app URL from the Streamlit dashboard.
- [ ] Test the deployed app with the included demo manifest.
- [ ] Do not submit a guessed or inaccessible deployment URL.

## Presentation materials

- [ ] Read `docs/DEMO_SCRIPT.md` and rehearse a three-minute walkthrough.
- [ ] Capture a screenshot of the actual running app and a results screen.
- [ ] Include the repository link and the verified live app URL in the submission form.
- [ ] Explain the risk score, data sources, remediation suggestions, and limitations.
- [ ] State clearly that the prototype finds known reported vulnerabilities and cannot prove that software is secure.

## Safety and reproducibility

- [ ] Never commit credentials, API keys, private manifests, or environment files.
- [ ] Do not use the demo manifest's old package pins in a production project.
- [ ] Review and test all suggested upgrades before applying them to a real application.
