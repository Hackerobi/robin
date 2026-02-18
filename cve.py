"""
cve.py — CVE Intelligence Module for Robin

Wraps the ProjectDiscovery /v2/vulnerability REST API directly from Python.
No Go binary (cvemap/vulnx) required — just needs a PDCP_API_KEY.

API Reference: https://api.projectdiscovery.io/docs
"""

import os
import json
import time
import hashlib
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from config import PDCP_API_KEY

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PDCP_BASE_URL = "https://api.projectdiscovery.io"
VULN_SEARCH_ENDPOINT = "/v2/vulnerability/search"
VULN_ID_ENDPOINT = "/v2/vulnerability/{cve_id}"
VULN_FILTERS_ENDPOINT = "/v2/vulnerability/filters"

DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 20

# Cache settings
CACHE_DIR = Path(os.getenv("CACHE_DIR", "./cache/cve"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_CVE", "21600"))  # 6 hours


# ---------------------------------------------------------------------------
# Cache Layer (simple file-based)
# ---------------------------------------------------------------------------
class CVECache:
    """Simple file-based JSON cache for CVE data."""

    def __init__(self, cache_dir: Path = CACHE_DIR, ttl: int = CACHE_TTL_SECONDS):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, key: str) -> Path:
        safe_key = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Optional[Dict]:
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            with open(path, "r") as f:
                cached = json.load(f)
            if time.time() - cached.get("_ts", 0) > self.ttl:
                path.unlink(missing_ok=True)
                return None
            return cached.get("data")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, key: str, data: Dict):
        path = self._key_path(key)
        try:
            with open(path, "w") as f:
                json.dump({"_ts": time.time(), "data": data}, f)
        except OSError as e:
            logger.warning(f"Cache write failed: {e}")

    def clear(self):
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)


_cache = CVECache()


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------
def _get_headers() -> Dict[str, str]:
    headers = {"User-Agent": "robin-cve/1.0", "Accept": "application/json"}
    api_key = PDCP_API_KEY
    if api_key:
        headers["X-PDCP-Key"] = api_key
    return headers


def _api_get(endpoint: str, params: Optional[Dict] = None) -> Dict:
    """Make a GET request to the ProjectDiscovery API."""
    url = PDCP_BASE_URL + endpoint
    try:
        resp = requests.get(
            url, headers=_get_headers(), params=params, timeout=DEFAULT_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"error": "not_found", "message": f"Resource not found: {endpoint}"}
        elif e.response.status_code == 429:
            raise RuntimeError(
                "ProjectDiscovery API rate limit exceeded. "
                "Set PDCP_API_KEY in your .env file for higher limits. "
                "Get a free key at https://cloud.projectdiscovery.io"
            ) from e
        elif e.response.status_code == 401:
            raise RuntimeError(
                "ProjectDiscovery API authentication failed. "
                "Check your PDCP_API_KEY in .env"
            ) from e
        else:
            raise RuntimeError(
                f"ProjectDiscovery API error ({e.response.status_code}): {e.response.text[:200]}"
            ) from e
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            "Cannot reach ProjectDiscovery API. Check your internet connection."
        ) from e
    except requests.exceptions.Timeout as e:
        raise RuntimeError("ProjectDiscovery API request timed out.") from e


# ---------------------------------------------------------------------------
# Public Functions
# ---------------------------------------------------------------------------
def lookup_cve(cve_id: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Look up a single CVE by its ID (e.g., 'CVE-2024-21887').

    Returns a structured dict with all vulnerability data from ProjectDiscovery,
    including CVSS, EPSS, KEV status, PoCs, affected products, weaknesses, etc.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    cache_key = f"lookup:{cve_id}"
    if use_cache:
        cached = _cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for {cve_id}")
            return cached

    endpoint = VULN_ID_ENDPOINT.format(cve_id=cve_id)
    raw = _api_get(endpoint)

    if raw.get("error") == "not_found":
        return {
            "found": False,
            "cve_id": cve_id,
            "error": f"CVE {cve_id} not found in ProjectDiscovery database",
        }

    # The API returns { "data": { ... vulnerability fields ... } }
    vuln = raw.get("data", raw)

    result = _normalize_vulnerability(vuln, cve_id)
    result["found"] = True

    if use_cache:
        _cache.set(cache_key, result)

    return result


def search_cves(
    query: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    min_epss: Optional[float] = None,
    kev_only: bool = False,
    has_poc: bool = False,
    has_template: bool = False,
    is_remote: bool = False,
    max_age_days: Optional[int] = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    Search for CVEs using the ProjectDiscovery search API with rich filtering.
    Builds a vulnx-style query string and sends it to /v2/vulnerability/search.
    """
    # Build the query string in vulnx syntax
    query_parts = []
    if query:
        query_parts.append(query)
    if vendor:
        query_parts.append(f"affected_products.vendor:{vendor}")
    if product:
        query_parts.append(f"product:{product}")
    if severity:
        query_parts.append(f"severity:{severity.lower()}")
    if min_cvss is not None:
        query_parts.append(f"cvss_score:>{min_cvss}")
    if min_epss is not None:
        query_parts.append(f"epss_score:>{min_epss}")
    if kev_only:
        query_parts.append("is_kev:true")
    if has_poc:
        query_parts.append("is_poc:true")
    if has_template:
        query_parts.append("is_template:true")
    if is_remote:
        query_parts.append("is_remote:true")
    if max_age_days is not None:
        query_parts.append(f"age_in_days:<{max_age_days}")

    q = " && ".join(query_parts) if query_parts else "is_kev:true"
    params = {"q": q, "limit": limit, "offset": offset}

    cache_key = f"search:{json.dumps(params, sort_keys=True)}"
    cached = _cache.get(cache_key)
    if cached:
        return cached

    raw = _api_get(VULN_SEARCH_ENDPOINT, params=params)

    results = []
    for vuln in raw.get("results", []):
        cve_id_inner = vuln.get("cve_id", "UNKNOWN")
        results.append(_normalize_vulnerability(vuln, cve_id_inner))

    response = {
        "total": raw.get("total", 0),
        "count": raw.get("count", len(results)),
        "vulnerabilities": results,
        "query_used": q,
    }

    _cache.set(cache_key, response)
    return response


def get_cve_summary_for_darkweb(cve_data: Dict) -> Dict[str, Any]:
    """
    Extract key fields from a CVE lookup that are useful for
    generating dark web search queries and for the final report.
    """
    if not cve_data.get("found", False):
        return cve_data

    return {
        "cve_id": cve_data.get("cve_id", ""),
        "description": cve_data.get("description", ""),
        "severity": cve_data.get("severity", ""),
        "cvss_score": cve_data.get("cvss_score", 0),
        "epss_score": cve_data.get("epss_score", 0),
        "epss_percentile": cve_data.get("epss_percentile", 0),
        "product": cve_data.get("product", ""),
        "vendor": cve_data.get("vendor", ""),
        "vulnerability_type": cve_data.get("vulnerability_type", ""),
        "is_kev": cve_data.get("is_kev", False),
        "is_remote": cve_data.get("is_remote", False),
        "has_poc": cve_data.get("has_poc", False),
        "poc_count": cve_data.get("poc_count", 0),
        "has_template": cve_data.get("has_template", False),
        "known_ransomware_use": cve_data.get("known_ransomware_use", False),
        "weaknesses": cve_data.get("weaknesses", []),
        "affected_products": cve_data.get("affected_products", []),
        "age_in_days": cve_data.get("age_in_days", 0),
    }


def check_pdcp_health() -> Dict[str, Any]:
    """Health check for the ProjectDiscovery API connection."""
    try:
        start = time.time()
        resp = requests.get(
            PDCP_BASE_URL + VULN_FILTERS_ENDPOINT,
            headers=_get_headers(),
            timeout=10,
        )
        latency_ms = round((time.time() - start) * 1000)
        if resp.status_code == 200:
            return {
                "status": "up",
                "latency_ms": latency_ms,
                "authenticated": bool(PDCP_API_KEY),
                "error": None,
            }
        else:
            return {
                "status": "down",
                "latency_ms": latency_ms,
                "authenticated": bool(PDCP_API_KEY),
                "error": f"HTTP {resp.status_code}",
            }
    except Exception as e:
        return {
            "status": "down",
            "latency_ms": None,
            "authenticated": bool(PDCP_API_KEY),
            "error": str(e)[:100],
        }


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------
def _normalize_vulnerability(vuln: Dict, cve_id: str) -> Dict[str, Any]:
    """
    Normalize a raw API vulnerability response into a clean, flat-ish dict
    that's easy to work with in Python / Streamlit / LLM prompts.
    """
    # Extract affected products list
    affected_products = []
    for ap in vuln.get("affected_products", []):
        affected_products.append({
            "vendor": ap.get("vendor", ""),
            "product": ap.get("product", ""),
            "category": ap.get("category", ""),
        })

    # Extract weaknesses
    weaknesses = []
    for w in vuln.get("weaknesses", []):
        weaknesses.append({
            "cwe_id": w.get("cwe_id", ""),
            "cwe_name": w.get("cwe_name", ""),
        })
    for cwe_id in vuln.get("cwe", []):
        if not any(w["cwe_id"] == cwe_id for w in weaknesses):
            weaknesses.append({"cwe_id": cwe_id, "cwe_name": ""})

    # Extract PoC URLs
    pocs = []
    for poc in vuln.get("pocs", []):
        pocs.append({
            "url": poc.get("url", ""),
            "source": poc.get("source", ""),
            "added_at": poc.get("added_at", ""),
        })

    # KEV details
    kev_info = {}
    known_ransomware_use = False
    for kev in vuln.get("kev", []):
        kev_info = {
            "added_date": kev.get("added_date", ""),
            "due_date": kev.get("due_date", ""),
            "source": kev.get("source", ""),
        }
        if kev.get("known_ransomware_campaign_use", False):
            known_ransomware_use = True

    # Exposure data
    exposure = vuln.get("exposure", {}) or {}

    return {
        "cve_id": vuln.get("cve_id", cve_id),
        "description": vuln.get("description", ""),
        "severity": vuln.get("severity", "unknown"),
        "cvss_score": vuln.get("cvss_score", 0),
        "cvss_metrics": vuln.get("cvss_metrics", ""),
        "epss_score": vuln.get("epss_score", 0),
        "epss_percentile": vuln.get("epss_percentile", 0),
        "product": vuln.get("product", ""),
        "vendor": vuln.get("vendor", ""),
        "vulnerability_type": vuln.get("vulnerability_type", ""),
        "vuln_status": vuln.get("vuln_status", ""),
        "age_in_days": vuln.get("age_in_days", 0),
        "is_kev": vuln.get("is_kev", False),
        "is_remote": vuln.get("is_remote", False),
        "has_poc": vuln.get("is_poc", False),
        "poc_count": vuln.get("poc_count", 0),
        "has_template": vuln.get("is_template", False),
        "known_ransomware_use": known_ransomware_use,
        "weaknesses": weaknesses,
        "affected_products": affected_products,
        "pocs": pocs,
        "kev_info": kev_info,
        "exposure": {
            "max_hosts": exposure.get("max_hosts", 0),
            "min_hosts": exposure.get("min_hosts", 0),
        },
        "assignee": vuln.get("assignee", ""),
        "remediation": vuln.get("remediation", ""),
        "impact": vuln.get("impact", ""),
        "cve_created_at": vuln.get("cve_created_at", ""),
        "cve_updated_at": vuln.get("cve_updated_at", ""),
        "h1_reports": (vuln.get("h1") or {}).get("reports", 0),
        "h1_rank": (vuln.get("h1") or {}).get("rank", 0),
    }
