"""
ui.py — Robin + CVE Dark Web Intelligence UI

Extends Robin's Streamlit UI with four tabs:
  1. CVE Lookup — Enter a CVE ID, get structured data + automatic dark web scan
  2. Dark Web Search — Existing Robin functionality (unchanged)
  3. Bulk CVE Monitor — Paste CVE list, get a risk dashboard
  4. Watch Center — Persistent monitoring of all investigated CVEs
"""

import os
import base64
import streamlit as st
from datetime import datetime
from scrape import scrape_multiple
from search import get_search_results
from llm_utils import BufferedStreamingHandler, get_model_choices
from llm import get_llm, refine_query, filter_results, generate_summary, PRESET_PROMPTS
from cve import lookup_cve, search_cves, check_pdcp_health
from cve_orchestrator import (
    generate_darkweb_queries, run_darkweb_search_multi, run_cve_investigation,
    run_bulk_cve_check, generate_cve_threat_report,
)
from watchlist import (
    get_watchlist, get_scan_history, get_watchlist_stats, get_change_log,
    get_trend_data, get_cves_due_for_rescan, update_priority, update_notes,
    archive_cve, reactivate_cve,
)
from config import (
    OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL, OLLAMA_BASE_URL, LLAMA_CPP_BASE_URL, PDCP_API_KEY,
)
from health import check_llm_health, check_search_engines, check_tor_proxy


def _find_logo():
    for path in [".github/assets/robin_logo.png", ".github/assets/logo.png",
                 "/app/.github/assets/robin_logo.png", "/app/.github/assets/logo.png"]:
        if os.path.exists(path):
            return path
    return None


def _render_pipeline_error(stage, err):
    message = str(err).strip() or err.__class__.__name__
    lower_msg = message.lower()
    hints = [
        "- Confirm the relevant API key is set in your `.env` or shell before launching Streamlit.",
        "- Keys copied from dashboards often include hidden spaces; re-copy if authentication keeps failing.",
        "- Restart the app after updating environment variables so the new values are picked up.",
    ]
    if any(t in lower_msg for t in ("anthropic", "x-api-key", "invalid api key", "authentication")):
        hints.insert(0, "- Claude/Anthropic models require a valid `ANTHROPIC_API_KEY`.")
    elif "openrouter" in lower_msg:
        hints.insert(0, "- OpenRouter models require `OPENROUTER_API_KEY`.")
    elif "openai" in lower_msg or "gpt" in lower_msg:
        hints.insert(0, "- OpenAI models require `OPENAI_API_KEY`.")
    elif "google" in lower_msg or "gemini" in lower_msg:
        hints.insert(0, "- Google Gemini models need `GOOGLE_API_KEY`.")
    elif "projectdiscovery" in lower_msg or "pdcp" in lower_msg:
        hints.insert(0, "- CVE features require `PDCP_API_KEY`. Free key: https://cloud.projectdiscovery.io")
    st.error("Failed to {}.\n\nError: {}\n\n{}".format(stage, message, "\n".join(hints)))
    st.stop()


def _env_is_set(value):
    return bool(value and str(value).strip() and "your_" not in str(value))


@st.cache_data(ttl=200, show_spinner=False)
def cached_search_results(refined_query, threads):
    return get_search_results(refined_query.replace(" ", "+"), max_workers=threads)


@st.cache_data(ttl=200, show_spinner=False)
def cached_scrape_multiple(filtered, threads):
    return scrape_multiple(filtered, max_workers=threads)


st.set_page_config(page_title="Robin: CVE Dark Web Intelligence", page_icon="🕵️", initial_sidebar_state="expanded", layout="wide")

st.markdown("""<style>
.colHeight { max-height: 40vh; overflow-y: auto; text-align: center; }
.pTitle { font-weight: bold; color: #FF4B4B; margin-bottom: 0.5em; }
.aStyle { font-size: 18px; font-weight: bold; padding: 5px; padding-left: 0px; text-align: center; }
</style>""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("Robin")
st.sidebar.text("CVE Dark Web Intelligence")
st.sidebar.markdown("""Made by [Apurv Singh Gautam](https://www.linkedin.com/in/apurvsinghgautam/)""")
st.sidebar.subheader("Settings")

model_options = get_model_choices()
default_model_index = next((idx for idx, name in enumerate(model_options) if name.lower() == "gpt4o"), 0) if model_options else 0

if not model_options:
    st.sidebar.error("No LLM models available. Set at least one API key in your `.env` file.")

model = st.sidebar.selectbox("Select LLM Model", model_options, index=default_model_index, key="model_select")
threads = st.sidebar.slider("Scraping Threads", 1, 16, 4, key="thread_slider")

st.sidebar.divider()
st.sidebar.subheader("Provider Configuration")
for name, value, is_cloud in [
    ("OpenAI", OPENAI_API_KEY, True), ("Anthropic", ANTHROPIC_API_KEY, True),
    ("Google", GOOGLE_API_KEY, True), ("OpenRouter", OPENROUTER_API_KEY, True),
    ("ProjectDiscovery", PDCP_API_KEY, True), ("Ollama", OLLAMA_BASE_URL, False),
    ("llama.cpp", LLAMA_CPP_BASE_URL, False),
]:
    if _env_is_set(value):
        st.sidebar.markdown(f"&ensp;✅ **{name}** — configured")
    elif is_cloud:
        st.sidebar.markdown(f"&ensp;⚠️ **{name}** — API key not set")
    else:
        st.sidebar.markdown(f"&ensp;🔵 **{name}** — not configured *(optional)*")

with st.sidebar.expander("Prompt Settings"):
    preset_options = {"Dark Web Threat Intel": "threat_intel", "Ransomware / Malware": "ransomware_malware",
                      "Personal / Identity": "personal_identity", "Corporate Espionage": "corporate_espionage"}
    preset_placeholders = {"threat_intel": "e.g. Pay extra attention to cryptocurrency wallet addresses.",
                           "ransomware_malware": "e.g. Highlight double-extortion tactics.",
                           "personal_identity": "e.g. Flag passport or ID numbers.",
                           "corporate_espionage": "e.g. Prioritize source code repositories."}
    selected_preset_label = st.selectbox("Research Domain", list(preset_options.keys()), key="preset_select")
    selected_preset = preset_options[selected_preset_label]
    st.text_area("System Prompt", value=PRESET_PROMPTS[selected_preset].strip(), height=200, disabled=True, key="system_prompt_display")
    custom_instructions = st.text_area("Custom Instructions (optional)", placeholder=preset_placeholders[selected_preset], height=100, key="custom_instructions")

st.sidebar.divider()
st.sidebar.subheader("Health Checks")

if st.sidebar.button("Check LLM Connection", use_container_width=True):
    with st.sidebar, st.spinner(f"Testing {model}..."):
        result = check_llm_health(model)
    if result["status"] == "up":
        st.sidebar.success(f"✅ **{result['provider']}** — Connected ({result['latency_ms']}ms)")
    else:
        st.sidebar.error(f"❌ **{result['provider']}** — Failed\n\n{result['error']}")

if st.sidebar.button("Check Search Engines", use_container_width=True):
    with st.sidebar, st.spinner("Checking Tor proxy..."):
        tor_result = check_tor_proxy()
    if tor_result["status"] == "down":
        st.sidebar.error(f"❌ **Tor Proxy** — Not reachable\n\n{tor_result['error']}")
    else:
        st.sidebar.success(f"✅ **Tor Proxy** — Connected ({tor_result['latency_ms']}ms)")
        with st.spinner("Pinging search engines via Tor..."):
            engine_results = check_search_engines()
        up_count = sum(1 for r in engine_results if r["status"] == "up")
        total = len(engine_results)
        if up_count == total:
            st.sidebar.success(f"✅ **All {total} engines reachable**")
        elif up_count > 0:
            st.sidebar.warning(f"⚠️ **{up_count}/{total} engines reachable**")
        else:
            st.sidebar.error(f"❌ **0/{total} engines reachable**")
        for r in engine_results:
            if r["status"] == "up":
                st.sidebar.markdown(f"&ensp;🟢 **{r['name']}** — {r['latency_ms']}ms")
            else:
                st.sidebar.markdown(f"&ensp;🔴 **{r['name']}** — {r['error']}")

if st.sidebar.button("Check CVE API", use_container_width=True):
    with st.sidebar, st.spinner("Testing ProjectDiscovery API..."):
        pdcp_result = check_pdcp_health()
    if pdcp_result["status"] == "up":
        auth_str = "authenticated" if pdcp_result["authenticated"] else "unauthenticated"
        st.sidebar.success(f"✅ **ProjectDiscovery** — Connected ({pdcp_result['latency_ms']}ms, {auth_str})")
    else:
        st.sidebar.error(f"❌ **ProjectDiscovery** — Failed\n\n{pdcp_result['error']}")

# Logo
_, logo_col, _ = st.columns(3)
with logo_col:
    logo_path = _find_logo()
    if logo_path:
        st.image(logo_path, width=200)
    else:
        st.markdown("# Robin")

# Tabs
tab_cve, tab_darkweb, tab_bulk, tab_watch = st.tabs(["CVE Lookup", "Dark Web Search", "Bulk CVE Monitor", "Watch Center"])

# === TAB 1: CVE LOOKUP ===
with tab_cve:
    st.markdown("### CVE Dark Web Threat Intelligence")
    st.caption("Enter a CVE ID to get structured vulnerability data and automatically scan the dark web for related chatter.")
    if not _env_is_set(PDCP_API_KEY):
        st.warning("PDCP_API_KEY not set. CVE lookups will be rate-limited. Get a free key at [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)")
    with st.form("cve_form", clear_on_submit=False):
        col_input, col_button = st.columns([10, 1])
        cve_input = col_input.text_input("Enter CVE ID", placeholder="CVE-2024-21887", label_visibility="collapsed", key="cve_input")
        cve_custom = st.text_area("Custom focus instructions (optional)", placeholder="e.g. Focus on ransomware group activity", height=68, key="cve_custom_instructions")
        cve_run = col_button.form_submit_button("🔍")
    cve_status = st.empty()
    cve_intel_container = st.empty()
    cve_darkweb_container = st.empty()
    cve_report_container = st.empty()

    if cve_run and cve_input:
        st.session_state.pop("cve_streamed_summary", None)
        with cve_status.container():
            with st.spinner("Loading LLM..."):
                try: llm = get_llm(model)
                except Exception as e: _render_pipeline_error("load the selected LLM", e)
        with cve_status.container():
            with st.spinner("Fetching CVE intelligence..."):
                try: cve_data = lookup_cve(cve_input)
                except Exception as e: _render_pipeline_error("fetch CVE data", e)
        if not cve_data.get("found", False):
            st.error(f"❌ {cve_data.get('error', 'CVE not found')}")
        else:
            with cve_intel_container.container(border=True):
                st.subheader("CVE Intelligence")
                c1, c2, c3, c4 = st.columns(4)
                severity = cve_data.get("severity", "unknown").upper()
                sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                c1.metric("Severity", f"{sev_emoji} {severity}")
                c2.metric("CVSS Score", f"{cve_data.get('cvss_score', 0):.1f}")
                c3.metric("EPSS Score", f"{cve_data.get('epss_score', 0):.4f}")
                c4.metric("Age (days)", cve_data.get("age_in_days", "—"))
                c5, c6, c7, c8 = st.columns(4)
                c5.metric("Product", cve_data.get("product", "—") or "—")
                c6.metric("Vendor", cve_data.get("vendor", "—") or "—")
                c7.metric("CISA KEV", "Yes" if cve_data.get("is_kev") else "No")
                poc_str = f"{cve_data.get('poc_count', 0)}" if cve_data.get("has_poc") else "No"
                c8.metric("Public PoCs", poc_str)
                c9, c10, c11, c12 = st.columns(4)
                c9.metric("Remote Exploit", "Yes" if cve_data.get("is_remote") else "No")
                c10.metric("Nuclei Template", "Yes" if cve_data.get("has_template") else "No")
                c11.metric("Ransomware Use", "Yes" if cve_data.get("known_ransomware_use") else "—")
                c12.metric("EPSS Percentile", f"{cve_data.get('epss_percentile', 0):.1%}")
                with st.expander("Full Description"):
                    st.write(cve_data.get("description", "No description available"))
                    if cve_data.get("weaknesses"):
                        st.write("**Weaknesses:**")
                        for w in cve_data["weaknesses"]:
                            st.write(f"- {w.get('cwe_id', '')} — {w.get('cwe_name', '')}")
            with cve_status.container():
                with st.spinner("Generating dark web search queries..."):
                    try: queries = generate_darkweb_queries(llm, cve_data)
                    except Exception as e: _render_pipeline_error("generate search queries", e)
            dw_status_text = st.empty()
            def _dw_progress(msg): dw_status_text.info(msg)
            with cve_status.container():
                with st.spinner("Searching the dark web..."):
                    search_results = run_darkweb_search_multi(queries, max_workers=threads, progress_callback=_dw_progress)
            dw_status_text.empty()
            with cve_darkweb_container.container(border=True):
                st.subheader("Dark Web Findings")
                total_hits = search_results.get("total_results", 0)
                if total_hits == 0: st.info("No dark web mentions found for this CVE.")
                elif total_hits < 5: st.warning(f"**{total_hits} mentions found** — Limited chatter.")
                elif total_hits < 15: st.warning(f"**{total_hits} mentions found** — Moderate activity.")
                else: st.error(f"**{total_hits} mentions found** — High dark web chatter!")
                with st.expander(f"Search Queries Used ({len(queries)})"):
                    for q in queries:
                        hits = search_results.get("results_per_query", {}).get(q, 0)
                        st.write(f"- `{q}` -> {hits} results")
                if total_hits > 0:
                    with st.expander(f"All Results ({total_hits})"):
                        for r in search_results.get("unique_results", []):
                            st.write(f"- [{r.get('title', 'Untitled')}]({r.get('link', '#')}) *(via: {r.get('source_query', '')})*")
            with cve_status.container():
                with st.spinner("Filtering results..."):
                    all_results = search_results.get("unique_results", [])
                    if all_results:
                        filter_query = f"{cve_input} {cve_data.get('product', '')} exploit vulnerability"
                        filtered = filter_results(llm, filter_query, all_results)
                        filtered = filtered[:20]
                    else:
                        filtered = []
            with cve_status.container():
                with st.spinner(f"Scraping {len(filtered)} pages..."):
                    scraped = scrape_multiple(filtered, max_workers=threads) if filtered else {}
            st.session_state.cve_streamed_summary = ""
            with cve_report_container.container():
                hdr_col, btn_col = st.columns([4, 1], vertical_alignment="center")
                with hdr_col:
                    st.subheader(":red[CVE Threat Intelligence Report]", anchor=None, divider="gray")
                report_slot = st.empty()
            def cve_ui_emit(chunk):
                st.session_state.cve_streamed_summary += chunk
                report_slot.markdown(st.session_state.cve_streamed_summary)
            with cve_status.container():
                with st.spinner("Generating threat intelligence report..."):
                    stream_handler = BufferedStreamingHandler(ui_callback=cve_ui_emit)
                    llm.callbacks = [stream_handler]
                    _ = generate_cve_threat_report(llm, cve_data, queries, scraped, cve_custom or "")
            with btn_col:
                now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                fname = f"cve_report_{cve_input}_{now}.md"
                b64 = base64.b64encode(st.session_state.cve_streamed_summary.encode()).decode()
                href = f'<div class="aStyle"><a href="data:file/markdown;base64,{b64}" download="{fname}">Download</a></div>'
                st.markdown(href, unsafe_allow_html=True)
            cve_status.success("CVE investigation complete!")


# === TAB 2: DARK WEB SEARCH (original Robin) ===
with tab_darkweb:
    st.markdown("### Dark Web OSINT Search")
    st.caption("Free-form dark web search — the original Robin experience.")
    with st.form("search_form", clear_on_submit=True):
        col_input, col_button = st.columns([10, 1])
        query = col_input.text_input("Enter Dark Web Search Query", placeholder="Enter Dark Web Search Query", label_visibility="collapsed", key="query_input")
        run_button = col_button.form_submit_button("Run")
    status_slot = st.empty()
    cols = st.columns(3)
    p1, p2, p3 = [col.empty() for col in cols]
    summary_container_placeholder = st.empty()

    if run_button and query:
        for k in ["refined", "results", "filtered", "scraped", "streamed_summary"]:
            st.session_state.pop(k, None)
        with status_slot.container():
            with st.spinner("Loading LLM..."):
                try: llm = get_llm(model)
                except Exception as e: _render_pipeline_error("load the selected LLM", e)
        with status_slot.container():
            with st.spinner("Refining query..."):
                try: st.session_state.refined = refine_query(llm, query)
                except Exception as e: _render_pipeline_error("refine the query", e)
        p1.container(border=True).markdown(f"<div class='colHeight'><p class='pTitle'>Refined Query</p><p>{st.session_state.refined}</p></div>", unsafe_allow_html=True)
        with status_slot.container():
            with st.spinner("Searching dark web..."):
                st.session_state.results = cached_search_results(st.session_state.refined, threads)
        p2.container(border=True).markdown(f"<div class='colHeight'><p class='pTitle'>Search Results</p><p>{len(st.session_state.results)}</p></div>", unsafe_allow_html=True)
        with status_slot.container():
            with st.spinner("Filtering results..."):
                st.session_state.filtered = filter_results(llm, st.session_state.refined, st.session_state.results)
        p3.container(border=True).markdown(f"<div class='colHeight'><p class='pTitle'>Filtered Results</p><p>{len(st.session_state.filtered)}</p></div>", unsafe_allow_html=True)
        with status_slot.container():
            with st.spinner("Scraping content..."):
                st.session_state.scraped = cached_scrape_multiple(st.session_state.filtered, threads)
        st.session_state.streamed_summary = ""
        def ui_emit(chunk):
            st.session_state.streamed_summary += chunk
            summary_slot.markdown(st.session_state.streamed_summary)
        with summary_container_placeholder.container():
            hdr_col, btn_col = st.columns([4, 1], vertical_alignment="center")
            with hdr_col:
                st.subheader(":red[Investigation Summary]", anchor=None, divider="gray")
            summary_slot = st.empty()
        with status_slot.container():
            with st.spinner("Generating summary..."):
                stream_handler = BufferedStreamingHandler(ui_callback=ui_emit)
                llm.callbacks = [stream_handler]
                _ = generate_summary(llm, query, st.session_state.scraped, preset=selected_preset, custom_instructions=custom_instructions)
        with btn_col:
            now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            fname = f"summary_{now}.md"
            b64 = base64.b64encode(st.session_state.streamed_summary.encode()).decode()
            href = f'<div class="aStyle"><a href="data:file/markdown;base64,{b64}" download="{fname}">Download</a></div>'
            st.markdown(href, unsafe_allow_html=True)
        status_slot.success("Pipeline completed successfully!")


# === TAB 3: BULK CVE MONITOR ===
with tab_bulk:
    st.markdown("### Bulk CVE Dark Web Monitor")
    st.caption("Paste a list of CVE IDs to check which ones have dark web activity.")
    if not _env_is_set(PDCP_API_KEY):
        st.warning("PDCP_API_KEY not set. Bulk lookups will be heavily rate-limited.")
    with st.form("bulk_form", clear_on_submit=False):
        bulk_input = st.text_area("CVE IDs (one per line)", placeholder="CVE-2024-21887\nCVE-2024-0519\nCVE-2023-44228", height=150, key="bulk_input")
        bulk_run = st.form_submit_button("Check All CVEs")
    bulk_status = st.empty()
    bulk_results_container = st.empty()

    if bulk_run and bulk_input:
        cve_ids = [line.strip() for line in bulk_input.strip().split("\n") if line.strip()]
        if not cve_ids:
            st.warning("Please enter at least one CVE ID.")
        elif len(cve_ids) > 25:
            st.warning("Please limit to 25 CVEs at a time.")
        else:
            with bulk_status.container():
                with st.spinner("Loading LLM..."):
                    try: llm = get_llm(model)
                    except Exception as e: _render_pipeline_error("load the selected LLM", e)
            progress_text = st.empty()
            def bulk_progress(msg): progress_text.info(msg)
            with bulk_status.container():
                with st.spinner("Checking CVEs against dark web..."):
                    results = run_bulk_cve_check(llm, cve_ids, threads=threads, progress_callback=bulk_progress)
            progress_text.empty()
            with bulk_results_container.container():
                st.subheader("CVE Risk Dashboard")
                total = len(results)
                critical_count = sum(1 for r in results if r.get("risk_level") == "CRITICAL")
                high_count = sum(1 for r in results if r.get("risk_level") == "HIGH")
                with_hits = sum(1 for r in results if r.get("darkweb_hits", 0) > 0)
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total CVEs", total)
                m2.metric("Critical", critical_count)
                m3.metric("High", high_count)
                m4.metric("DW Hits", with_hits)
                st.divider()
                risk_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5, "ERROR": 6}
                results.sort(key=lambda r: risk_order.get(r.get("risk_level", "UNKNOWN"), 99))
                for r in results:
                    risk = r.get("risk_level", "UNKNOWN")
                    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🟢", "INFORMATIONAL": "🔵"}.get(risk, "⚪")
                    cve_id = r.get("cve_id", "?")
                    dw_hits = r.get("darkweb_hits", 0)
                    if not r.get("found", False):
                        st.markdown(f"**{cve_id}** — Not found in database")
                        continue
                    col_a, col_b, col_c, col_d, col_e, col_f = st.columns([2, 1, 1, 1, 1, 1])
                    col_a.markdown(f"**{cve_id}**")
                    col_b.markdown(f"{risk_emoji} {risk}")
                    col_c.markdown(f"**{r.get('severity', '?').upper()}** ({r.get('cvss_score', 0):.1f})")
                    col_d.markdown(f"EPSS: {r.get('epss_score', 0):.3f}")
                    col_e.markdown(f"KEV: {'Yes' if r.get('is_kev') else '—'}")
                    col_f.markdown(f"DW: **{dw_hits}**" if dw_hits > 0 else "DW: —")
                st.divider()
                import json as json_mod
                results_json = json_mod.dumps(results, indent=2, default=str)
                now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                st.download_button("Download Results (JSON)", data=results_json, file_name=f"cve_bulk_report_{now}.json", mime="application/json")
            bulk_status.success("Bulk CVE check complete!")


# === TAB 4: WATCH CENTER ===
with tab_watch:
    st.markdown("### CVE Watch Center")
    st.caption("Every CVE you investigate is automatically saved here. Re-scan to detect new dark web chatter.")
    try:
        stats = get_watchlist_stats()
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Watched CVEs", stats.get("total_watched", 0))
        s2.metric("Total Scans", stats.get("total_scans", 0))
        s3.metric("With New Activity", stats.get("with_new_activity", 0))
        s4.metric("Need Rescan (24h+)", stats.get("needs_rescan", 0))
    except Exception:
        st.info("No watchlist data yet. Investigate a CVE in the CVE Lookup tab to start building your watchlist.")
    st.divider()
    watch_col_a, watch_col_b = st.columns([3, 1])
    with watch_col_a:
        st.markdown("#### Watchlist")
    with watch_col_b:
        rescan_all = st.button("Rescan All Stale CVEs", use_container_width=True, key="rescan_all_btn")

    if rescan_all:
        stale_cves = get_cves_due_for_rescan(max_age_hours=24)
        if not stale_cves:
            st.success("All watched CVEs have been scanned within the last 24 hours.")
        else:
            with st.spinner("Loading LLM..."):
                try: llm = get_llm(model)
                except Exception as e: _render_pipeline_error("load the selected LLM", e)
            rescan_progress = st.empty()
            rescan_bar = st.progress(0)
            for i, cve_row in enumerate(stale_cves):
                cve_id = cve_row["cve_id"]
                rescan_progress.info(f"Re-scanning {cve_id} ({i+1}/{len(stale_cves)})...")
                rescan_bar.progress((i + 1) / len(stale_cves))
                try:
                    from cve import lookup_cve as _lookup
                    cve_data = _lookup(cve_id, use_cache=False)
                    if cve_data.get("found"):
                        queries = generate_darkweb_queries(llm, cve_data)
                        search_results = run_darkweb_search_multi(queries, max_workers=threads)
                        from cve_orchestrator import _assess_quick_risk
                        from watchlist import save_cve as _save_cve, save_scan_results as _save_scan
                        _save_cve(cve_data)
                        _save_scan(cve_id, cve_data, search_results, risk_level=_assess_quick_risk(cve_data, search_results.get("total_results", 0)))
                except Exception as e:
                    st.warning(f"Failed to rescan {cve_id}: {str(e)[:100]}")
            rescan_progress.empty()
            rescan_bar.empty()
            st.success(f"Re-scanned {len(stale_cves)} CVEs.")
            st.rerun()

    try: watchlist = get_watchlist(active_only=True)
    except Exception: watchlist = []

    if not watchlist:
        st.info("Your watchlist is empty. Go to **CVE Lookup** and investigate a CVE — it will automatically appear here.")
    else:
        hdr = st.columns([2, 1, 1, 1, 1, 1, 1, 1])
        hdr[0].markdown("**CVE ID**"); hdr[1].markdown("**Severity**"); hdr[2].markdown("**DW Hits**")
        hdr[3].markdown("**Trend**"); hdr[4].markdown("**Last Scan**"); hdr[5].markdown("**Risk**")
        hdr[6].markdown("**Priority**"); hdr[7].markdown("**Actions**")
        for idx, cve in enumerate(watchlist):
            cols = st.columns([2, 1, 1, 1, 1, 1, 1, 1])
            cols[0].markdown(f"**{cve['cve_id']}**")
            sev = (cve.get("severity") or "—").upper()
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            cols[1].markdown(f"{sev_emoji} {sev}")
            hits = cve.get("latest_hits") or 0
            delta = cve.get("latest_delta") or 0
            delta_str = f" (+{delta})" if delta > 0 else (f" ({delta})" if delta < 0 else "")
            cols[2].markdown(f"**{hits}**{delta_str}")
            trend = cve.get("trend", "new")
            trend_emoji = {"rising": "📈", "falling": "📉", "stable": "➡️", "new": "🆕"}.get(trend, "❓")
            cols[3].markdown(f"{trend_emoji} {trend}")
            last_scan = cve.get("last_scanned")
            if last_scan:
                try:
                    dt = datetime.fromisoformat(last_scan)
                    age = datetime.utcnow() - dt
                    if age.total_seconds() < 3600: age_str = f"{int(age.total_seconds() / 60)}m ago"
                    elif age.total_seconds() < 86400: age_str = f"{int(age.total_seconds() / 3600)}h ago"
                    else: age_str = f"{age.days}d ago"
                except (ValueError, TypeError): age_str = "—"
            else: age_str = "never"
            cols[4].markdown(age_str)
            risk = cve.get("latest_risk", "—") or "—"
            risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🟢", "INFORMATIONAL": "🔵"}.get(risk, "⚪")
            cols[5].markdown(f"{risk_emoji} {risk}")
            priority = cve.get("priority", "normal")
            pri_emoji = {"critical": "🔴", "high": "🟠", "normal": "⚪", "low": "🔵"}.get(priority, "⚪")
            cols[6].markdown(f"{pri_emoji} {priority}")
            with cols[7]:
                if st.button("🔍", key=f"detail_{idx}", help="View details"):
                    st.session_state[f"expand_{cve['cve_id']}"] = not st.session_state.get(f"expand_{cve['cve_id']}", False)
            if st.session_state.get(f"expand_{cve['cve_id']}", False):
                with st.container(border=True):
                    det_c1, det_c2 = st.columns(2)
                    with det_c1:
                        st.markdown(f"**{cve['cve_id']}** — {cve.get('product', '')} ({cve.get('vendor', '')})")
                        st.markdown(f"CVSS: **{cve.get('cvss_score', 0):.1f}** | EPSS: **{cve.get('epss_score', 0):.4f}** | KEV: {'Yes' if cve.get('is_kev') else 'No'} | PoC: {'Yes' if cve.get('has_poc') else 'No'} | Ransomware: {'Yes' if cve.get('known_ransomware_use') else '—'}")
                        st.caption(cve.get("description", "")[:300])
                        new_links = cve.get("latest_new_links", [])
                        if new_links:
                            st.markdown(f"**{len(new_links)} new links in latest scan:**")
                            for link in new_links[:10]: st.markdown(f"- `{link}`")
                    with det_c2:
                        new_pri = st.selectbox("Priority", ["critical", "high", "normal", "low"], index=["critical", "high", "normal", "low"].index(priority), key=f"pri_{cve['cve_id']}")
                        if new_pri != priority:
                            update_priority(cve['cve_id'], new_pri); st.rerun()
                        current_notes = cve.get("notes", "")
                        new_notes = st.text_area("Analyst Notes", value=current_notes, height=80, key=f"notes_{cve['cve_id']}")
                        if new_notes != current_notes:
                            if st.button("Save Notes", key=f"save_notes_{cve['cve_id']}"):
                                update_notes(cve['cve_id'], new_notes); st.success("Notes saved.")
                        trend_data = get_trend_data(cve['cve_id'], limit=20)
                        if len(trend_data) >= 2:
                            import pandas as pd
                            df = pd.DataFrame(trend_data)
                            df["scanned_at"] = pd.to_datetime(df["scanned_at"])
                            st.line_chart(df.set_index("scanned_at")["total_hits"], height=150)
                        elif trend_data: st.caption(f"1 scan recorded ({trend_data[0].get('total_hits', 0)} hits)")
                        else: st.caption("No scan history yet")
                        if st.button("Archive", key=f"archive_{cve['cve_id']}"): archive_cve(cve['cve_id']); st.rerun()

    st.divider()
    st.markdown("#### Change Log")
    st.caption("Recent scans that detected changes in dark web chatter.")
    try: changes = get_change_log(limit=30)
    except Exception: changes = []
    if not changes:
        st.info("No changes recorded yet.")
    else:
        for ch in changes:
            delta = ch.get("delta_hits", 0)
            new_links = ch.get("new_links", [])
            cve_id = ch.get("cve_id", "?")
            ts = ch.get("scanned_at", "?")
            if delta > 0: emoji, delta_str = "🔺", f"+{delta} new mentions"
            elif delta < 0: emoji, delta_str = "🔻", f"{delta} mentions (decreased)"
            else: emoji, delta_str = "🆕", f"First scan — {ch.get('total_hits', 0)} hits"
            risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🟢"}.get(ch.get("risk_level", ""), "⚪")
            st.markdown(f"{emoji} **{cve_id}** — {delta_str} | {risk_emoji} {ch.get('risk_level', '—')} | {ts}")
            if new_links and delta > 0:
                with st.expander(f"New links ({len(new_links)})"):
                    for link in new_links[:10]: st.markdown(f"- `{link}`")

    with st.expander("Archived CVEs"):
        try: archived = [c for c in get_watchlist(active_only=False) if not c.get("is_active")]
        except Exception: archived = []
        if not archived: st.info("No archived CVEs.")
        else:
            for cve in archived:
                ac1, ac2 = st.columns([4, 1])
                ac1.markdown(f"**{cve['cve_id']}** — {cve.get('product', '')} ({cve.get('severity', '').upper()})")
                if ac2.button("Reactivate", key=f"react_{cve['cve_id']}"): reactivate_cve(cve['cve_id']); st.rerun()
