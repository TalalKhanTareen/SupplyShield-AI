SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Unknown": 0
}


def calculate_risk(findings):
    total = sum(
        SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "Unknown")).title(),
            0
        )
        for finding in findings
    )
    return min(total * 10, 100)


def get_risk_level(score):
    score = max(0, min(int(score), 100))

    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score > 0:
        return "Low"

    return "No known findings"
