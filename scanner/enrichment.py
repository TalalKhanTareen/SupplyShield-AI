"""Free, key-less threat-intelligence enrichment.

Sources (all free, no API key required):
  * PyPI JSON API   - latest release, yanked releases        https://pypi.org
  * FIRST.org EPSS  - probability a CVE is exploited soon    https://api.first.org
  * CISA KEV        - CVEs known to be exploited in the wild https://www.cisa.gov

Every function fails soft: a network problem returns an error entry instead of
raising, so a scan never crashes because an enrichment source is down.
"""
from packaging.version import InvalidVersion, Version
import requests

PYPI_URL = "https://pypi.org/pypi/{name}/json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
TIMEOUT = 15
EPSS_BATCH_SIZE = 50


def get_package_info(name, installed_version):
    """Look up the latest release and yanked status for a pinned package."""
    try:
        response = requests.get(PYPI_URL.format(name=name), timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as error:
        return {"status": "error", "error": str(error)}

    latest = data.get("info", {}).get("version")
    files = data.get("releases", {}).get(installed_version, [])
    yanked = bool(files) and all(item.get("yanked") for item in files)

    outdated = None
    try:
        if latest:
            outdated = Version(installed_version) < Version(latest)
    except InvalidVersion:
        pass

    if yanked:
        state = "Yanked"
    elif outdated is None:
        state = "Unknown"
    elif outdated:
        state = "Outdated"
    else:
        state = "Up to date"

    return {
        "status": "success",
        "latest_version": latest,
        "outdated": outdated,
        "yanked": yanked,
        "state": state,
        "error": None,
    }


def get_epss_scores(cve_ids):
    """Return ({cve: {"epss": float, "percentile": float}}, error_or_None)."""
    unique = sorted({cve.upper() for cve in cve_ids})
    scores = {}

    try:
        for start in range(0, len(unique), EPSS_BATCH_SIZE):
            batch = unique[start:start + EPSS_BATCH_SIZE]
            response = requests.get(
                EPSS_URL, params={"cve": ",".join(batch)}, timeout=TIMEOUT
            )
            response.raise_for_status()
            for row in response.json().get("data", []):
                scores[row["cve"].upper()] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
    except (requests.RequestException, ValueError, KeyError) as error:
        return scores, str(error)

    return scores, None


def get_kev_catalog():
    """Return ({cve: date_added}, error_or_None) from the CISA KEV catalog."""
    try:
        response = requests.get(KEV_URL, timeout=TIMEOUT)
        response.raise_for_status()
        catalog = {
            item["cveID"].upper(): item.get("dateAdded")
            for item in response.json().get("vulnerabilities", [])
        }
        return catalog, None
    except (requests.RequestException, ValueError, KeyError) as error:
        return {}, str(error)


def _cve_ids(finding):
    candidates = [finding.get("vulnerability_id", "")] + list(
        finding.get("aliases", [])
    )
    return sorted({c.upper() for c in candidates if str(c).upper().startswith("CVE-")})


def enrich_findings(findings, epss_lookup=get_epss_scores, kev_lookup=get_kev_catalog):
    """Add CVE, EPSS and CISA-KEV data to findings.

    Returns (findings, warnings). Findings are modified copies; warnings is a
    list of human-readable strings for sources that could not be reached.
    """
    warnings = []
    enriched = [dict(item) for item in findings]

    for item in enriched:
        item["cve_ids"] = _cve_ids(item)
        item["epss"] = None
        item["epss_percentile"] = None
        item["known_exploited"] = False

    all_cves = sorted({cve for item in enriched for cve in item["cve_ids"]})
    if not all_cves:
        return enriched, warnings

    epss, epss_error = epss_lookup(all_cves)
    if epss_error:
        warnings.append(f"EPSS lookup incomplete: {epss_error}")

    kev, kev_error = kev_lookup()
    if kev_error:
        warnings.append(f"CISA KEV lookup failed: {kev_error}")

    for item in enriched:
        scored = [epss[c] for c in item["cve_ids"] if c in epss]
        if scored:
            best = max(scored, key=lambda s: s["epss"])
            item["epss"] = best["epss"]
            item["epss_percentile"] = best["percentile"]
        item["known_exploited"] = any(c in kev for c in item["cve_ids"])

    return enriched, warnings
