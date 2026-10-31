from scanner.risk_engine import calculate_risk, get_risk_level


def test_empty_findings():
    assert calculate_risk([]) == 0


def test_critical_finding():
    assert calculate_risk([{"severity": "Critical"}]) == 100


def test_low_finding():
    assert calculate_risk([{"severity": "Low"}]) == 10


def test_repeated_findings_are_counted():
    assert calculate_risk([
        {"severity": "Low"},
        {"severity": "Low"},
        {"severity": "Medium"}
    ]) == 60


def test_score_is_capped():
    assert calculate_risk([
        {"severity": "Critical"},
        {"severity": "High"}
    ]) == 100


def test_unknown_severity():
    assert calculate_risk([{"severity": "Unknown"}]) == 0


def test_case_insensitive_severity():
    assert calculate_risk([{"severity": "high"}]) == 70


def test_risk_level():
    assert get_risk_level(90) == "Critical"
    assert get_risk_level(70) == "High"
    assert get_risk_level(40) == "Medium"
    assert get_risk_level(10) == "Low"
    assert get_risk_level(0) == "No known findings"
