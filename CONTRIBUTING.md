# Contributing

Thanks for helping improve SupplyShield AI.

## Before making a change

1. Open an issue to discuss larger features or behavior changes.
2. Keep changes focused and explain the motivation.
3. Never commit API keys, credentials, private manifests, or environment files.

## Development setup

```bash
python -m venv .venv
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Activate the virtual environment using the command appropriate for your operating system.

## Validation

Run the tests before submitting a pull request:

```bash
python -m pytest -q
```

For UI changes, run `streamlit run app.py`, test both the upload and demo-manifest flows, verify that incomplete lookups are clearly shown, and check CSV/JSON downloads.

## Pull requests

Include a short summary, motivation, test results, and screenshots for substantial UI changes. Avoid claiming that a dependency is safe solely because the scanner returned no known findings.
