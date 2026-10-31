SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Unknown": 0
}


def calculate_risk(findings):
    if not findings:
        return 0

    weights = [
        SEVERITY_WEIGHTS.get(
            finding.get("severity", "Unknown"),
            0
        )
        for finding in findings
    ]

    total = max(weights)

    for weight in weights:
        if weight != total:
            total += weight

    return min(total * 10, 100)


def get_risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score > 0:
        return "Low"

    return "No known findings"
