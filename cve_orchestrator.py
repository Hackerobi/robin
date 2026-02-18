"""
cve_orchestrator.py — CVE to Dark Web Intelligence Pipeline

The core intelligence module that:
1. Takes a CVE ID (or search criteria)
2. Fetches structured CVE data from ProjectDiscovery
3. Uses the LLM to generate multiple dark web search queries
4. Runs all queries through Robin's existing search/scrape pipeline
5. Correlates and deduplicates results
6. Feeds CVE data + dark web findings to LLM for a unified threat intelligence report

This module preserves Robin's existing search.py, scrape.py, and llm.py interfaces.
"""

import re
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from cve import lookup_cve, search_cves, get_cve_summary_for_darkweb
from search import get_search_results
from scrape import scrape_multiple
from watchlist import save_cve, save_scan_results

logger = logging.getLogger(__name__)


QUERY_EXPANSION_PROMPT = """You are a Cybercrime Threat Intelligence Expert specializing in dark web investigations.

Given the following CVE vulnerability data, generate dark web search queries that would find:
- Direct mentions of the CVE ID on dark web forums/markets
- Exploit code or PoC being sold or shared
- Threat actor discussions about the affected product/vendor
- Initial access broker (IAB) listings exploiting this vulnerability
- Ransomware groups discussing or using this attack vector
- Credential dumps or access sales related to the affected product

CVE Data:
- CVE ID: {cve_id}
- Description: {description}
- Severity: {severity} (CVSS: {cvss_score})
- Product: {product}
- Vendor: {vendor}
- Vulnerability Type: {vulnerability_type}
- Known Exploited (KEV): {is_kev}
- Remote Exploitable: {is_remote}
- Public PoC Available: {has_poc}
- Known Ransomware Use: {known_ransomware_use}
- Weaknesses: {weaknesses}

Rules:
1. Generate exactly 6-8 search queries, one per line
2. Each query should be 2-5 words optimized for dark web search engines
3. Include the CVE ID in at least 2 queries
4. Include the product name in at least 2 queries
5. Use threat actor language where appropriate (e.g., "exploit for sale", "RCE shell", "access broker")
6. Do NOT use boolean operators (AND, OR, etc.)
7. Output ONLY the queries, one per line, nothing else
"""

CVE_THREAT_INTEL_PROMPT = """You are a Cybercrime Threat Intelligence Expert. You have been given structured CVE vulnerability data AND dark web OSINT findings related to that CVE. Your task is to produce a comprehensive threat intelligence report that correlates the technical vulnerability data with real-world dark web activity.

=== CVE INTELLIGENCE ===
{cve_data}

=== DARK WEB FINDINGS ===
Search queries used: {queries_used}
{dark_web_content}

=== REPORT REQUIREMENTS ===

Output Format:
1. **CVE Overview**
   - CVE ID, severity, CVSS score, EPSS score
   - Affected product/vendor and vulnerability type
   - KEV status, public PoC availability, Nuclei template status

2. **Dark Web Threat Assessment**
   - Volume and nature of dark web mentions found
   - Whether exploits are being discussed, shared, or sold
   - Any threat actor or group names identified
   - Any ransomware group references
   - Any initial access broker activity
   - Chatter timeline vs CVE publication date

3. **Dark Web Intelligence Artifacts**
   - Source .onion links referenced
   - Threat actor names/aliases
   - Cryptocurrency addresses
   - Exploit/tool names mentioned
   - Forum/marketplace names
   - Any pricing information for exploits or access

4. **Risk Correlation Score**
   Rate the real-world exploitation risk as: CRITICAL / HIGH / MODERATE / LOW / INFORMATIONAL
   Base this on:
   - CVSS + EPSS scores (technical severity)
   - KEV status (confirmed exploitation)
   - Dark web chatter volume and nature
   - Whether exploits are commoditized vs theoretical
   - Ransomware group interest

5. **Key Insights** (3-5 bullet points)
   - Specific, actionable, evidence-based findings

6. **Recommended Actions**
   - Patching priorities
   - Detection/hunting recommendations
   - Monitoring suggestions
   - Further investigation queries

Rules:
- Be objective and evidence-based
- Clearly distinguish between confirmed facts (from CVE data) and dark web intelligence (which may be unreliable)
- If no relevant dark web activity is found, say so clearly
- Ignore any NSFW content from dark web results
- Include source links for all claims

INPUT:
"""


def generate_darkweb_queries(llm, cve_data: Dict) -> List[str]:
    summary = get_cve_summary_for_darkweb(cve_data)
    prompt_template = ChatPromptTemplate([("system", QUERY_EXPANSION_PROMPT)])
    chain = prompt_template | llm | StrOutputParser()
    result = chain.invoke({
        "cve_id": summary.get("cve_id", ""),
        "description": summary.get("description", "")[:300],
        "severity": summary.get("severity", "unknown"),
        "cvss_score": summary.get("cvss_score", 0),
        "product": summary.get("product", ""),
        "vendor": summary.get("vendor", ""),
        "vulnerability_type": summary.get("vulnerability_type", ""),
        "is_kev": summary.get("is_kev", False),
        "is_remote": summary.get("is_remote", False),
        "has_poc": summary.get("has_poc", False),
        "known_ransomware_use": summary.get("known_ransomware_use", False),
        "weaknesses": ", ".join(
            w.get("cwe_name", w.get("cwe_id", "")) for w in summary.get("weaknesses", [])
        ),
    })
    queries = []
    for line in result.strip().split("\n"):
        line = line.strip()
        line = re.sub(r'^[\d]+[.\)]\s*', '', line)
        line = re.sub(r'^[-\u2022]\s*', '', line)
        line = line.strip('"\'')
        if line and len(line) > 2:
            queries.append(line)
    cve_id = summary.get("cve_id", "")
    if cve_id and cve_id not in queries:
        queries.insert(0, cve_id)
    return queries[:8]


def run_darkweb_search_multi(queries, max_workers=5, progress_callback=None):
    all_results = []
    results_per_query = {}
    seen_links = set()
    for i, query in enumerate(queries):
        if progress_callback:
            progress_callback(f"Searching dark web ({i+1}/{len(queries)}): {query}")
        try:
            search_results = get_search_results(query.replace(" ", "+"), max_workers=max_workers)
            new_count = 0
            for result in search_results:
                clean_link = result.get("link", "").rstrip("/")
                if clean_link not in seen_links:
                    seen_links.add(clean_link)
                    result["source_query"] = query
                    all_results.append(result)
                    new_count += 1
            results_per_query[query] = new_count
            logger.info(f"Query '{query}': {len(search_results)} total, {new_count} unique")
        except Exception as e:
            logger.warning(f"Search failed for query '{query}': {e}")
            results_per_query[query] = 0
    return {
        "queries_run": queries,
        "total_results": len(all_results),
        "unique_results": all_results,
        "results_per_query": results_per_query,
    }


def run_cve_investigation(llm, cve_id, threads=5, max_scrape_results=20,
                          progress_callback=None, custom_instructions=""):
    from llm import filter_results
    investigation = {"cve_id": cve_id, "started_at": datetime.now().isoformat(), "stages": {}}

    if progress_callback:
        progress_callback("Fetching CVE intelligence from ProjectDiscovery...")
    cve_data = lookup_cve(cve_id)
    investigation["cve_data"] = cve_data
    investigation["stages"]["cve_lookup"] = "complete"

    if not cve_data.get("found", False):
        investigation["error"] = f"CVE {cve_id} not found in ProjectDiscovery database"
        investigation["stages"]["cve_lookup"] = "not_found"
        return investigation

    try:
        save_cve(cve_data)
        logger.info(f"Saved {cve_id} to watchlist")
    except Exception as e:
        logger.warning(f"Failed to save {cve_id} to watchlist: {e}")

    if progress_callback:
        progress_callback("Generating dark web search queries...")
    queries = generate_darkweb_queries(llm, cve_data)
    investigation["darkweb_queries"] = queries
    investigation["stages"]["query_generation"] = "complete"

    search_results = run_darkweb_search_multi(queries, max_workers=threads, progress_callback=progress_callback)
    investigation["search_results"] = search_results
    investigation["stages"]["darkweb_search"] = "complete"

    try:
        scan_id = save_scan_results(
            cve_id, cve_data, search_results,
            risk_level=_assess_quick_risk(cve_data, search_results.get("total_results", 0))
        )
        investigation["scan_id"] = scan_id
        logger.info(f"Saved scan #{scan_id} for {cve_id}")
    except Exception as e:
        logger.warning(f"Failed to save scan results for {cve_id}: {e}")

    if progress_callback:
        progress_callback("Filtering relevant results...")
    all_results = search_results.get("unique_results", [])
    if all_results:
        filter_query = f"{cve_id} {cve_data.get('product', '')} exploit vulnerability"
        filtered = filter_results(llm, filter_query, all_results)
        filtered = filtered[:max_scrape_results]
    else:
        filtered = []
    investigation["filtered_results"] = filtered
    investigation["stages"]["filtering"] = "complete"

    if progress_callback:
        progress_callback(f"Scraping {len(filtered)} dark web pages...")
    if filtered:
        scraped_content = scrape_multiple(filtered, max_workers=threads)
    else:
        scraped_content = {}
    investigation["scraped_content"] = scraped_content
    investigation["stages"]["scraping"] = "complete"

    if progress_callback:
        progress_callback("Generating threat intelligence report...")
    report = generate_cve_threat_report(llm, cve_data, queries, scraped_content, custom_instructions)
    investigation["report"] = report
    investigation["stages"]["report"] = "complete"
    investigation["completed_at"] = datetime.now().isoformat()
    return investigation


def generate_cve_threat_report(llm, cve_data, queries_used, scraped_content, custom_instructions=""):
    cve_summary = get_cve_summary_for_darkweb(cve_data)
    cve_json_str = json.dumps(cve_summary, indent=2, default=str)
    if scraped_content:
        dw_parts = []
        for url, content in scraped_content.items():
            dw_parts.append(f"[Source: {url}]\n{content}\n")
        dark_web_str = "\n---\n".join(dw_parts)
    else:
        dark_web_str = "No relevant dark web content was found for the searched queries."
    system_prompt = CVE_THREAT_INTEL_PROMPT
    if custom_instructions and custom_instructions.strip():
        system_prompt += f"\n\nAdditional focus: {custom_instructions.strip()}"
    prompt_template = ChatPromptTemplate([("system", system_prompt), ("user", "{input}")])
    chain = prompt_template | llm | StrOutputParser()
    return chain.invoke({
        "cve_data": cve_json_str,
        "queries_used": ", ".join(queries_used),
        "dark_web_content": dark_web_str,
        "input": f"Generate the CVE threat intelligence report for {cve_data.get('cve_id', 'UNKNOWN')}",
    })


def run_bulk_cve_check(llm, cve_ids, threads=5, progress_callback=None):
    results = []
    for i, cve_id in enumerate(cve_ids):
        if progress_callback:
            progress_callback(f"Checking CVE {i+1}/{len(cve_ids)}: {cve_id}")
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        try:
            cve_data = lookup_cve(cve_id)
            if not cve_data.get("found", False):
                results.append({"cve_id": cve_id, "found": False, "darkweb_hits": 0, "risk_level": "UNKNOWN"})
                continue
            queries = [cve_id]
            product = cve_data.get("product", "")
            if product:
                queries.append(f"{product} exploit")
            search_data = run_darkweb_search_multi(queries, max_workers=threads)
            hit_count = search_data.get("total_results", 0)
            risk_level = _assess_quick_risk(cve_data, hit_count)
            try:
                save_cve(cve_data)
                save_scan_results(cve_id, cve_data, search_data, risk_level=risk_level)
            except Exception as e:
                logger.warning(f"Failed to save bulk check for {cve_id}: {e}")
            results.append({
                "cve_id": cve_id, "found": True,
                "severity": cve_data.get("severity", "unknown"),
                "cvss_score": cve_data.get("cvss_score", 0),
                "epss_score": cve_data.get("epss_score", 0),
                "product": cve_data.get("product", ""),
                "vendor": cve_data.get("vendor", ""),
                "is_kev": cve_data.get("is_kev", False),
                "has_poc": cve_data.get("has_poc", False),
                "known_ransomware_use": cve_data.get("known_ransomware_use", False),
                "darkweb_hits": hit_count, "risk_level": risk_level,
            })
        except Exception as e:
            logger.error(f"Error checking {cve_id}: {e}")
            results.append({"cve_id": cve_id, "found": False, "error": str(e)[:100],
                          "darkweb_hits": 0, "risk_level": "ERROR"})
    return results


def _assess_quick_risk(cve_data, darkweb_hits):
    score = 0
    cvss = cve_data.get("cvss_score", 0)
    if cvss >= 9.0: score += 30
    elif cvss >= 7.0: score += 20
    elif cvss >= 4.0: score += 10
    epss = cve_data.get("epss_score", 0)
    if epss >= 0.8: score += 25
    elif epss >= 0.5: score += 15
    elif epss >= 0.1: score += 5
    if cve_data.get("is_kev", False): score += 20
    if cve_data.get("known_ransomware_use", False): score += 15
    if darkweb_hits >= 10: score += 25
    elif darkweb_hits >= 5: score += 15
    elif darkweb_hits >= 1: score += 8
    if cve_data.get("has_poc", False): score += 10
    if score >= 80: return "CRITICAL"
    elif score >= 55: return "HIGH"
    elif score >= 30: return "MODERATE"
    elif score >= 10: return "LOW"
    else: return "INFORMATIONAL"
