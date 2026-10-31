SEVERITY_WEIGHTS = {
    "Critical": 90,
    "High": 70,
    "Medium": 40,
    "Low": 15,
    "Unknown": 5
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Unknown": 4
}

PRIORITY_ORDER = {
    "Urgent": 0,
    "Elevated": 1,
    "Standard": 2
}


def _unique_findings(findings):
    groups = []

    for finding in findings:
        identifiers = {
            str(value).strip().upper()
            for value in [
                finding.get("vulnerability_id", ""),
                *finding.get("aliases", [])
            ]
            if value
        }

        identifiers.add(
            f"{finding.get('package', '').lower()}:{finding.get('installed_version', '')}:{finding.get('vulnerability_id', '')}"
        )

        matching_groups = [
            group for group in groups
            if group["identifiers"] & identifiers
        ]

        if not matching_groups:
            groups.append({
                "identifiers": identifiers,
                "findings": [finding]
            })
        else:
            primary = matching_groups[0]
            primary["identifiers"].update(identifiers)
            primary["findings"].append(finding)

            for other in matching_groups[1:]:
                primary["identifiers"].update(other["identifiers"])
                primary["findings"].extend(other["findings"])
                groups.remove(other)

    unique = []

    for group in groups:
        best = max(
            group["findings"],
            key=lambda finding: SEVERITY_ORDER.get(
                str(finding.get("severity", "Unknown")).title(),
                4
            )
        )
        unique.append(best)

    return unique


def calculate_risk(findings):
    unique = _unique_findings(findings)

    if not unique:
        return 0

    severity_scores = [
        SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "Unknown")).title(),
            5
        )
        for finding in unique
    ]

    highest_score = max(severity_scores)
    additional_findings_score = (len(unique) - 1) * 3

    return min(highest_score + additional_findings_score, 100)


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


def get_priority(finding):
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
    return sorted(
        findings,
        key=lambda finding: (
            PRIORITY_ORDER[get_priority(finding)],
            SEVERITY_ORDER.get(
                str(finding.get("severity", "Unknown")).title(),
                4
            )
        )
    )
