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


PRIORITY_ORDER = {"Urgent": 0, "Elevated": 1, "Standard": 2}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


def get_priority(finding):
    """Remediation priority using real-world exploit intelligence.

    Urgent   - listed in CISA KEV (exploited in the wild) or EPSS >= 50%
    Elevated - EPSS >= 10%
    Standard - everything else
    """
    if finding.get("known_exploited"):
        return "Urgent"

    epss = finding.get("epss")
    if epss is not None:
        if epss >= 0.5:
            return "Urgent"
        if epss >= 0.1:
            return "Elevated"

    return "Standard"


def sort_findings(findings):
    """Order findings by remediation priority, then severity."""
    return sorted(
        findings,
        key=lambda f: (
            PRIORITY_ORDER[get_priority(f)],
            SEVERITY_ORDER.get(str(f.get("severity", "Unknown")).title(), 4),
        ),
    )
