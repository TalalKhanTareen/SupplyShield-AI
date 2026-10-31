import json

from scanner.report_generator import generate_report


def test_report_is_valid_json_and_contains_scan_summary():
    report = generate_report(
        dependencies=[{"name": "requests", "version": "2.31.0"}],
        findings=[{"vulnerability_id": "CVE-2025-12345", "severity": "High"}],
        errors=[],
        risk_score=70,
        warnings=["Example warning"],
    )
    parsed = json.loads(report)
    assert parsed["project"] == "SupplyShield AI"
    assert parsed["dependencies_analyzed"] == 1
    assert parsed["vulnerabilities_found"] == 1
    assert parsed["risk_score"] == 70
    assert parsed["warnings"] == ["Example warning"]
    assert parsed["scan_timestamp"]
