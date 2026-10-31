from scanner.risk_engine import calculate_risk, get_risk_level


def test_empty_findings():
    assert calculate_risk([]) == 0


def test_critical_finding():
    findings = [{"severity": "Critical"}]
    assert calculate_risk(findings) == 100


def test_low_finding():
    findings = [{"severity": "Low"}]
    assert calculate_risk(findings) == 10


def test_unknown_severity():
    findings = [{"severity": "Unknown"}]
    assert calculate_risk(findings) == 0


def test_risk_level():
    assert get_risk_level(90) == "Critical"
    assert get_risk_level(70) == "High"
    assert get_risk_level(40) == "Medium"
    assert get_risk_level(10) == "Low"
    assert get_risk_level(0) == "No known findings"
