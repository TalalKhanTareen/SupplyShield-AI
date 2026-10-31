SEVERITY_WEIGHTS = {
    "Critical": 90,
    "High": 70,
    "Medium": 40,
    "Low": 15,
    "Unknown": 5,
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Unknown": 4,
}

PRIORITY_ORDER = {
    "Urgent": 0,
    "Elevated": 1,
    "Standard": 2,
}


def deduplicate_findings(findings):
    """Merge duplicate OSV advisories for the same package and installed version."""
    groups = []

    for finding in findings:
        package_key = (
            str(finding.get("package", "")).strip().lower(),
            str(finding.get("installed_version", "")).strip(),
        )
        identifiers = {
            str(value).strip().upper()
            for value in [
                finding.get("vulnerability_id", ""),
                *finding.get("aliases", []),
            ]
            if value and str(value).strip().upper() != "UNKNOWN"
        }

        matches = [
            group for group in groups
            if group["package_key"] == package_key
            and group["identifiers"] & identifiers
        ]

        if not matches:
            groups.append({
                "package_key": package_key,
                "identifiers": set(identifiers),
                "findings": [finding],
            })
            continue

        primary = matches[0]
        primary["identifiers"].update(identifiers)
        primary["findings"].append(finding)

        for other in matches[1:]:
            primary["identifiers"].update(other["identifiers"])
            primary["findings"].extend(other["findings"])
            groups.remove(other)

    unique = []

    for group in groups:
        items = group["findings"]
        best = dict(max(
            items,
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item.get("severity", "Unknown")).title(), 4),
                bool(item.get("summary")),
            ),
        ))

        aliases = set()
        references = set()
        cve_ids = set()
        for item in items:
            aliases.update(str(value) for value in item.get("aliases", []) if value)
            references.update(str(value) for value in item.get("references", []) if value)
            cve_ids.update(str(value) for value in item.get("cve_ids", []) if value)

        best["aliases"] = sorted(aliases)
        best["references"] = sorted(references)
        if cve_ids:
            best["cve_ids"] = sorted(cve_ids)

        epss_values = [
            float(item["epss"])
            for item in items
            if item.get("epss") is not None
        ]
        best["epss"] = max(epss_values) if epss_values else None

        percentile_values = [
            float(item["epss_percentile"])
            for item in items
            if item.get("epss_percentile") is not None
        ]
        best["epss_percentile"] = max(percentile_values) if percentile_values else None
        best["known_exploited"] = any(item.get("known_exploited", False) for item in items)

        preferred_ids = sorted(
            {
                str(item.get("vulnerability_id", "")).strip()
                for item in items
                if item.get("vulnerability_id")
            },
            key=lambda value: (
                0 if value.upper().startswith("GHSA-") else
                1 if value.upper().startswith("CVE-") else
                2 if value.upper().startswith("PYSEC-") else 3,
                value,
            ),
        )
        if preferred_ids:
            best["vulnerability_id"] = preferred_ids[0]

        unique.append(best)

    return unique


def calculate_risk(findings):
    unique = deduplicate_findings(findings)

    if not unique:
        return 0

    severity_scores = [
        SEVERITY_WEIGHTS.get(
            str(finding.get("severity", "Unknown")).title(),
            5,
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
        try:
            epss = float(epss)
        except (TypeError, ValueError):
            epss = None

        if epss is not None:
            if epss > 1:
                epss /= 100
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
                4,
            ),
        ),
    )
