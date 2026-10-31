import requests

from scanner import enrichment
from scanner.enrichment import enrich_findings, get_package_info
from scanner.risk_engine import get_priority, sort_findings


class FakeResponse:
    def __init__(self, payload, fail=False):
        self._payload = payload
        self._fail = fail

    def raise_for_status(self):
        if self._fail:
            raise requests.HTTPError("boom")

    def json(self):
        return self._payload


def test_package_info_outdated(monkeypatch):
    payload = {"info": {"version": "2.32.0"}, "releases": {"2.28.1": [{"yanked": False}]}}
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **k: FakeResponse(payload))
    info = get_package_info("requests", "2.28.1")
    assert info["state"] == "Outdated"
    assert info["latest_version"] == "2.32.0"


def test_package_info_yanked(monkeypatch):
    payload = {"info": {"version": "2.0"}, "releases": {"1.0": [{"yanked": True}]}}
    monkeypatch.setattr(enrichment.requests, "get", lambda *a, **k: FakeResponse(payload))
    assert get_package_info("pkg", "1.0")["state"] == "Yanked"


def test_package_info_network_error(monkeypatch):
    def fail(*a, **k):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(enrichment.requests, "get", fail)
    assert get_package_info("pkg", "1.0")["status"] == "error"


def test_enrich_findings_adds_epss_and_kev():
    findings = [{"vulnerability_id": "GHSA-xxxx", "aliases": ["CVE-2024-0001"], "severity": "High"}]
    enriched, warnings = enrich_findings(
        findings,
        epss_lookup=lambda cves: ({"CVE-2024-0001": {"epss": 0.7, "percentile": 0.98}}, None),
        kev_lookup=lambda: ({"CVE-2024-0001": "2024-01-01"}, None),
    )
    assert warnings == []
    assert enriched[0]["epss"] == 0.7
    assert enriched[0]["known_exploited"] is True
    assert "epss" not in findings[0]  # input is not mutated


def test_enrichment_failure_is_a_warning_not_a_crash():
    findings = [{"vulnerability_id": "CVE-2024-0002", "aliases": []}]
    enriched, warnings = enrich_findings(
        findings,
        epss_lookup=lambda cves: ({}, "timeout"),
        kev_lookup=lambda: ({}, "timeout"),
    )
    assert len(warnings) == 2
    assert enriched[0]["epss"] is None


def test_findings_without_cves_skip_lookups():
    def explode(*a, **k):
        raise AssertionError("should not be called")

    enriched, warnings = enrich_findings(
        [{"vulnerability_id": "PYSEC-1", "aliases": []}], explode, explode
    )
    assert warnings == [] and enriched[0]["cve_ids"] == []


def test_priority_levels():
    assert get_priority({"known_exploited": True}) == "Urgent"
    assert get_priority({"epss": 0.6}) == "Urgent"
    assert get_priority({"epss": 0.2}) == "Elevated"
    assert get_priority({"epss": 0.01}) == "Standard"
    assert get_priority({}) == "Standard"


def test_sort_puts_urgent_first():
    ordered = sort_findings([
        {"id": "a", "severity": "Critical"},
        {"id": "b", "severity": "Low", "known_exploited": True},
    ])
    assert ordered[0]["id"] == "b"
