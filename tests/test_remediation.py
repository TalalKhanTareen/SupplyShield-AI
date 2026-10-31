from scanner.remediation import build_fixed_requirements, suggest_upgrades

DEPS = [
    {"name": "Flask", "version": "2.2.2"},
    {"name": "requests", "version": "2.28.1"},
]


def test_picks_highest_newer_fix():
    findings = [
        {"package": "flask", "fixed_version": "2.2.5"},
        {"package": "Flask", "fixed_version": "3.0.1"},
    ]
    assert suggest_upgrades(DEPS, findings) == [
        {"package": "Flask", "current": "2.2.2", "target": "3.0.1"}
    ]


def test_ignores_fix_older_than_current():
    assert suggest_upgrades(DEPS, [{"package": "requests", "fixed_version": "2.0.0"}]) == []


def test_ignores_missing_or_invalid_fix():
    findings = [
        {"package": "requests", "fixed_version": None},
        {"package": "requests", "fixed_version": "not-a-version"},
    ]
    assert suggest_upgrades(DEPS, findings) == []


def test_fixed_requirements_output():
    upgrades = [{"package": "Flask", "current": "2.2.2", "target": "3.0.1"}]
    text = build_fixed_requirements(DEPS, upgrades)
    assert "Flask==3.0.1" in text
    assert "requests==2.28.1" in text
