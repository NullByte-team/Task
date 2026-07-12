"""
NullByte Tool - CVE Lookup Engine
Queries the NIST NVD API v2 and ExploitDB (via searchsploit if available)
to find CVEs related to a service name / product version.
Results are cached in memory to avoid repeated API calls.
"""

import re
import time
import subprocess
import threading
import requests
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from functools import lru_cache


NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_BASE = "https://cve.circl.lu/api/search"   # fallback
REQUEST_TIMEOUT = 20
RATE_LIMIT_DELAY = 0.6   # seconds between NVD requests (respect rate limits)

_nvd_lock = threading.Lock()
_last_nvd_call = 0.0


@dataclass
class CVEEntry:
    """A single CVE record."""
    cve_id:       str
    description:  str
    cvss_v3:      float
    cvss_v2:      float
    severity:     str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    references:   List[str] = field(default_factory=list)
    exploit_db_id: Optional[str] = None   # ExploitDB ID if found
    has_exploit:  bool = False
    published:    str = ""
    source_url:   str = ""

    @property
    def cvss(self) -> float:
        """Best available CVSS score."""
        return self.cvss_v3 if self.cvss_v3 > 0 else self.cvss_v2

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    @property
    def exploitdb_url(self) -> Optional[str]:
        if self.exploit_db_id:
            return f"https://www.exploit-db.com/exploits/{self.exploit_db_id}"
        return None


# ─── In-memory cache ──────────────────────────────────────────────────────────
_cache: Dict[str, List[CVEEntry]] = {}


def lookup_cves(
    product: str,
    version: str,
    service: str = "",
    max_results: int = 8,
) -> List[CVEEntry]:
    """
    Main entry point: look up CVEs for a given product/version.
    Returns a sorted list (highest CVSS first).
    """
    # Build cache key
    query = _build_query(product, version, service)
    if not query:
        return []

    cache_key = query.lower()
    if cache_key in _cache:
        return _cache[cache_key]

    cves: List[CVEEntry] = []

    # 1. Try NVD API
    try:
        cves = _query_nvd(query, max_results)
    except Exception:
        pass

    # 2. Fallback to CIRCL if NVD returned nothing
    if not cves:
        try:
            cves = _query_circl(product, version, max_results)
        except Exception:
            pass

    # 3. Check ExploitDB via searchsploit (if installed)
    try:
        _enrich_with_exploitdb(cves, product, version)
    except Exception:
        pass

    # Sort by CVSS descending
    cves.sort(key=lambda c: c.cvss, reverse=True)

    _cache[cache_key] = cves
    return cves


# ─── NVD API ──────────────────────────────────────────────────────────────────

def _rate_limit():
    global _last_nvd_call
    with _nvd_lock:
        now = time.time()
        gap = now - _last_nvd_call
        if gap < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - gap)
        _last_nvd_call = time.time()


def _query_nvd(keyword: str, max_results: int) -> List[CVEEntry]:
    _rate_limit()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "keywordExactMatch": False,
    }
    headers = {"User-Agent": "NullByte-PenTest-Tool/1.0"}

    resp = requests.get(
        NVD_API_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    data = resp.json()

    entries: List[CVEEntry] = []
    for item in data.get("vulnerabilities", []):
        cve_node = item.get("cve", {})
        entry = _parse_nvd_entry(cve_node)
        if entry:
            entries.append(entry)

    return entries


def _parse_nvd_entry(cve_node: Dict[str, Any]) -> Optional[CVEEntry]:
    cve_id = cve_node.get("id", "")
    if not cve_id:
        return None

    # Description (English preferred)
    descriptions = cve_node.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    # CVSS scores
    cvss_v3 = 0.0
    cvss_v2 = 0.0
    severity = "NONE"

    metrics = cve_node.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            m = metric_list[0].get("cvssData", {})
            cvss_v3 = float(m.get("baseScore", 0))
            severity = m.get("baseSeverity", severity)
            break

    if not metrics.get("cvssMetricV31") and not metrics.get("cvssMetricV30"):
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            m = v2_list[0].get("cvssData", {})
            cvss_v2 = float(m.get("baseScore", 0))

    # Published date
    published = cve_node.get("published", "")[:10]

    # References
    refs = [
        r.get("url", "")
        for r in cve_node.get("references", [])
        if r.get("url")
    ][:5]

    return CVEEntry(
        cve_id=cve_id,
        description=desc,
        cvss_v3=cvss_v3,
        cvss_v2=cvss_v2,
        severity=severity,
        references=refs,
        published=published,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


# ─── CIRCL Fallback ───────────────────────────────────────────────────────────

def _query_circl(product: str, version: str, max_results: int) -> List[CVEEntry]:
    query = f"{product} {version}".strip()
    if not query:
        return []

    url = f"{CIRCL_API_BASE}/{requests.utils.quote(product)}/{requests.utils.quote(version)}"
    resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    entries = []
    for item in data[:max_results]:
        cve_id = item.get("id", "")
        if not cve_id:
            continue

        cvss = float(item.get("cvss", 0))
        desc = item.get("summary", "")

        entries.append(CVEEntry(
            cve_id=cve_id,
            description=desc,
            cvss_v3=cvss,
            cvss_v2=0.0,
            severity=_cvss_to_severity(cvss),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))

    return entries


# ─── ExploitDB Enrichment ─────────────────────────────────────────────────────

def _enrich_with_exploitdb(cves: List[CVEEntry], product: str, version: str) -> None:
    """Try to find exploits via searchsploit CLI."""
    try:
        result = subprocess.run(
            ["searchsploit", "--json", f"{product} {version}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout:
            return

        import json
        data = json.loads(result.stdout)
        exploits = data.get("RESULTS_EXPLOIT", [])

        # Map CVE IDs from exploit descriptions
        for exploit in exploits:
            edb_id = str(exploit.get("EDB-ID", ""))
            title  = exploit.get("Title", "").lower()

            for cve in cves:
                cve_lower = cve.cve_id.lower()
                if cve_lower in title:
                    cve.has_exploit = True
                    if not cve.exploit_db_id:
                        cve.exploit_db_id = edb_id
                    break
            else:
                # Mark product-matching exploits as "potential exploit"
                pass

        # If we found any exploit, set the first CVE's exploit flag
        if exploits and cves and not cves[0].has_exploit:
            cves[0].has_exploit = True
            cves[0].exploit_db_id = str(exploits[0].get("EDB-ID", ""))

    except (FileNotFoundError, Exception):
        pass   # searchsploit not installed — skip silently


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _build_query(product: str, version: str, service: str) -> str:
    """Build a meaningful search query."""
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    if service:
        return service
    return ""


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score >= 0.1:  return "LOW"
    return "NONE"


def clear_cache():
    """Clear the in-memory CVE cache."""
    global _cache
    _cache = {}
