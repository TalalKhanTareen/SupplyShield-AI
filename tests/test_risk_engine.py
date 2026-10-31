from scanner.risk_engine import (
    calculate_risk,
    deduplicate_findings,
    get_priority,
    get_risk_level,
    sort_findings,
)


def finding(severity, package, version="1.0", vuln_id=None, **extra):
    item = {
        "severity": severity,
        "package": package,
        "installed_version": version,
        "aliases": [],
    }
    if vuln_id:
        item["vulnerability_id"] = vuln_id
    item.update(extra)
    return item


def test_empty_findings_have_zero_risk():
    assert calculate_risk([]) == 0


def test_severity_weights_are_applied():
    assert calculate_risk([finding("Critical", "alpha", vuln_id="CVE-2026-0001")]) == 90
    assert calculate_risk([finding("High", "beta", vuln_id="CVE-2026-0002")]) == 70
    assert calculate_risk([finding("Medium", "gamma", vuln_id="CVE-2026-0003")]) == 40
    assert calculate_risk([finding("Low", "delta", vuln_id="CVE-2026-0004")]) == 15
    assert calculate_risk([finding("Unknown", "epsilon", vuln_id="GHSA-AAAA-BBBB-CCCC")]) == 5


def test_additional_distinct_findings_increase_risk():
    items = [
        finding("Low", "alpha", vuln_id="CVE-2026-0001"),
        finding("Low", "beta", vuln_id="CVE-2026-0002"),
        finding("Medium", "gamma", vuln_id="CVE-2026-0003"),
    ]
    assert calculate_risk(items) == 46


def test_risk_score_is_capped_at_100():
    items = [finding("Critical", f"pkg{i}", vuln_id=f"CVE-2026-{i:04d}") for i in range(5)]
    assert calculate_risk(items) == 100


def test_risk_levels():
    assert get_risk_level(90) == "Critical"
    assert get_risk_level(70) == "High"
    assert get_risk_level(40) == "Medium"
    assert get_risk_level(15) == "Low"
    assert get_risk_level(0) == "No known findings"


def test_related_advisories_are_deduplicated():
    items = [
        finding("High", "requests", "2.0", "GHSA-AAAA-BBBB-CCCC", aliases=["CVE-2026-0001"]),
        finding("Critical", "requests", "2.0", "CVE-2026-0001", aliases=["GHSA-AAAA-BBBB-CCCC"]),
    ]
    result = deduplicate_findings(items)
    assert len(result) == 1
    assert result[0]["severity"] == "Critical"
    assert "CVE-2026-0001" in result[0]["aliases"] or result[0]["vulnerability_id"] == "CVE-2026-0001"


def test_priority_uses_kev_then_epss():
    assert get_priority({"known_exploited": True, "epss": 0.01}) == "Urgent"
    assert get_priority({"known_exploited": False, "epss": 0.7}) == "Urgent"
    assert get_priority({"known_exploited": False, "epss": 0.2}) == "Elevated"
    assert get_priority({"known_exploited": False, "epss": 0.02}) == "Standard"


def test_findings_sort_by_priority_then_severity():
    items = [
        finding("Critical", "alpha", vuln_id="CVE-2026-0001", epss=0.01),
        finding("Low", "beta", vuln_id="CVE-2026-0002", epss=0.8),
        finding("High", "gamma", vuln_id="CVE-2026-0003", known_exploited=True),
    ]
    ordered = sort_findings(items)
    assert ordered[0]["package"] == "beta"
    assert ordered[1]["package"] == "gamma"
    assert ordered[2]["package"] == "alpha"
