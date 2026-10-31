import json
from datetime import datetime, timezone


def generate_report(dependencies, findings, errors, risk_score):
    report = {
        "project": "SupplyShield AI",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies_analyzed": len(dependencies),
        "vulnerabilities_found": len(findings),
        "risk_score": risk_score,
        "dependencies": dependencies,
        "findings": findings,
        "errors": errors
    }

    return json.dumps(report, indent=2)
