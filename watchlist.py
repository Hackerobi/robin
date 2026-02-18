"""
watchlist.py — CVE Watchlist & Monitoring Database

SQLite-backed persistence layer that:
  - Automatically saves every CVE that gets investigated
  - Stores scan history with dark web results per scan
  - Computes deltas between scans (new mentions, new sources)
  - Calculates chatter trends (rising / falling / stable)
  - Tracks CVE metadata changes over time (EPSS changes, KEV flips, new PoCs)

Database location: ./data/robin_watchlist.db (volume-mount /app/data in Docker)
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

DB_DIR = Path(os.getenv("ROBIN_DATA_DIR", "./data"))
DB_PATH = DB_DIR / "robin_watchlist.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS watched_cves (
    cve_id          TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_scanned    TEXT,
    priority        TEXT NOT NULL DEFAULT 'normal',
    notes           TEXT DEFAULT '',
    is_active       INTEGER NOT NULL DEFAULT 1,
    severity        TEXT DEFAULT '',
    cvss_score      REAL DEFAULT 0,
    epss_score      REAL DEFAULT 0,
    epss_percentile REAL DEFAULT 0,
    product         TEXT DEFAULT '',
    vendor          TEXT DEFAULT '',
    is_kev          INTEGER DEFAULT 0,
    has_poc         INTEGER DEFAULT 0,
    has_template    INTEGER DEFAULT 0,
    known_ransomware_use INTEGER DEFAULT 0,
    description     TEXT DEFAULT '',
    vulnerability_type TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    scanned_at      TEXT NOT NULL DEFAULT (datetime('now')),
    total_hits      INTEGER DEFAULT 0,
    unique_links    INTEGER DEFAULT 0,
    queries_used    TEXT DEFAULT '[]',
    results_per_query TEXT DEFAULT '{}',
    epss_score      REAL DEFAULT 0,
    cvss_score      REAL DEFAULT 0,
    is_kev          INTEGER DEFAULT 0,
    has_poc         INTEGER DEFAULT 0,
    risk_level      TEXT DEFAULT '',
    delta_hits      INTEGER DEFAULT 0,
    new_links       TEXT DEFAULT '[]',
    FOREIGN KEY (cve_id) REFERENCES watched_cves(cve_id)
);

CREATE TABLE IF NOT EXISTS darkweb_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    cve_id          TEXT NOT NULL,
    link            TEXT NOT NULL,
    title           TEXT DEFAULT '',
    source_query    TEXT DEFAULT '',
    first_seen_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scan_history(id),
    FOREIGN KEY (cve_id) REFERENCES watched_cves(cve_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_history_cve ON scan_history(cve_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_darkweb_results_cve ON darkweb_results(cve_id);
CREATE INDEX IF NOT EXISTS idx_darkweb_results_link ON darkweb_results(link);
"""


def _get_db() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA_SQL)
    return conn


def save_cve(cve_data: Dict[str, Any], priority: str = "normal") -> None:
    conn = _get_db()
    try:
        conn.execute("""
            INSERT INTO watched_cves (
                cve_id, priority, severity, cvss_score, epss_score, epss_percentile,
                product, vendor, is_kev, has_poc, has_template, known_ransomware_use,
                description, vulnerability_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                epss_score = excluded.epss_score,
                epss_percentile = excluded.epss_percentile,
                product = excluded.product,
                vendor = excluded.vendor,
                is_kev = excluded.is_kev,
                has_poc = excluded.has_poc,
                has_template = excluded.has_template,
                known_ransomware_use = excluded.known_ransomware_use,
                description = excluded.description,
                vulnerability_type = excluded.vulnerability_type
        """, (
            cve_data.get("cve_id", ""),
            priority,
            cve_data.get("severity", ""),
            cve_data.get("cvss_score", 0),
            cve_data.get("epss_score", 0),
            cve_data.get("epss_percentile", 0),
            cve_data.get("product", ""),
            cve_data.get("vendor", ""),
            1 if cve_data.get("is_kev") else 0,
            1 if cve_data.get("has_poc") else 0,
            1 if cve_data.get("has_template") else 0,
            1 if cve_data.get("known_ransomware_use") else 0,
            cve_data.get("description", "")[:500],
            cve_data.get("vulnerability_type", ""),
        ))
        conn.commit()
    finally:
        conn.close()


def save_scan_results(cve_id, cve_data, search_results, risk_level=""):
    conn = _get_db()
    try:
        total_hits = search_results.get("total_results", 0)
        unique_results = search_results.get("unique_results", [])
        queries_used = search_results.get("queries_run", [])
        results_per_query = search_results.get("results_per_query", {})

        prev = conn.execute("""
            SELECT id, total_hits FROM scan_history
            WHERE cve_id = ? ORDER BY scanned_at DESC LIMIT 1
        """, (cve_id,)).fetchone()

        current_links = {r.get("link", "").rstrip("/") for r in unique_results if r.get("link")}
        existing_links = set()
        for row in conn.execute(
            "SELECT DISTINCT link FROM darkweb_results WHERE cve_id = ?", (cve_id,)
        ):
            existing_links.add(row["link"].rstrip("/"))

        new_links = list(current_links - existing_links)
        delta_hits = total_hits - (prev["total_hits"] if prev else 0)

        cursor = conn.execute("""
            INSERT INTO scan_history (
                cve_id, total_hits, unique_links, queries_used, results_per_query,
                epss_score, cvss_score, is_kev, has_poc, risk_level,
                delta_hits, new_links
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id, total_hits, len(current_links),
            json.dumps(queries_used), json.dumps(results_per_query),
            cve_data.get("epss_score", 0), cve_data.get("cvss_score", 0),
            1 if cve_data.get("is_kev") else 0,
            1 if cve_data.get("has_poc") else 0,
            risk_level, delta_hits, json.dumps(new_links[:100]),
        ))
        scan_id = cursor.lastrowid

        for r in unique_results:
            link = r.get("link", "").rstrip("/")
            if link:
                conn.execute("""
                    INSERT INTO darkweb_results (scan_id, cve_id, link, title, source_query)
                    VALUES (?, ?, ?, ?, ?)
                """, (scan_id, cve_id, link, r.get("title", ""), r.get("source_query", "")))

        conn.execute(
            "UPDATE watched_cves SET last_scanned = datetime('now') WHERE cve_id = ?",
            (cve_id,)
        )
        conn.commit()
        return scan_id
    finally:
        conn.close()


def get_watchlist(active_only=True):
    conn = _get_db()
    try:
        where = "WHERE w.is_active = 1" if active_only else ""
        rows = conn.execute(f"""
            SELECT w.*,
                (SELECT COUNT(*) FROM scan_history s WHERE s.cve_id = w.cve_id) as scan_count,
                (SELECT total_hits FROM scan_history s WHERE s.cve_id = w.cve_id ORDER BY s.scanned_at DESC LIMIT 1) as latest_hits,
                (SELECT delta_hits FROM scan_history s WHERE s.cve_id = w.cve_id ORDER BY s.scanned_at DESC LIMIT 1) as latest_delta,
                (SELECT risk_level FROM scan_history s WHERE s.cve_id = w.cve_id ORDER BY s.scanned_at DESC LIMIT 1) as latest_risk,
                (SELECT new_links FROM scan_history s WHERE s.cve_id = w.cve_id ORDER BY s.scanned_at DESC LIMIT 1) as latest_new_links
            FROM watched_cves w {where}
            ORDER BY w.last_scanned DESC NULLS LAST
        """).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["trend"] = _calculate_trend(conn, d["cve_id"])
            try:
                d["latest_new_links"] = json.loads(d.get("latest_new_links") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["latest_new_links"] = []
            results.append(d)
        return results
    finally:
        conn.close()


def get_scan_history(cve_id, limit=20):
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT * FROM scan_history WHERE cve_id = ?
            ORDER BY scanned_at DESC LIMIT ?
        """, (cve_id, limit)).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["queries_used"] = json.loads(d.get("queries_used") or "[]")
                d["results_per_query"] = json.loads(d.get("results_per_query") or "{}")
                d["new_links"] = json.loads(d.get("new_links") or "[]")
            except (json.JSONDecodeError, TypeError):
                pass
            results.append(d)
        return results
    finally:
        conn.close()


def get_new_findings_since(cve_id, since=None):
    if since is None:
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT DISTINCT dr.link, dr.title, dr.source_query, dr.first_seen_at, sh.scanned_at
            FROM darkweb_results dr JOIN scan_history sh ON dr.scan_id = sh.id
            WHERE dr.cve_id = ? AND dr.first_seen_at > ?
            ORDER BY dr.first_seen_at DESC
        """, (cve_id, since)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_known_links(cve_id):
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT DISTINCT link FROM darkweb_results WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        return {row["link"].rstrip("/") for row in rows}
    finally:
        conn.close()


def update_priority(cve_id, priority):
    conn = _get_db()
    try:
        conn.execute("UPDATE watched_cves SET priority = ? WHERE cve_id = ?", (priority, cve_id))
        conn.commit()
    finally:
        conn.close()


def update_notes(cve_id, notes):
    conn = _get_db()
    try:
        conn.execute("UPDATE watched_cves SET notes = ? WHERE cve_id = ?", (notes, cve_id))
        conn.commit()
    finally:
        conn.close()


def archive_cve(cve_id):
    conn = _get_db()
    try:
        conn.execute("UPDATE watched_cves SET is_active = 0 WHERE cve_id = ?", (cve_id,))
        conn.commit()
    finally:
        conn.close()


def reactivate_cve(cve_id):
    conn = _get_db()
    try:
        conn.execute("UPDATE watched_cves SET is_active = 1 WHERE cve_id = ?", (cve_id,))
        conn.commit()
    finally:
        conn.close()


def delete_cve(cve_id):
    conn = _get_db()
    try:
        conn.execute("DELETE FROM darkweb_results WHERE cve_id = ?", (cve_id,))
        conn.execute("DELETE FROM scan_history WHERE cve_id = ?", (cve_id,))
        conn.execute("DELETE FROM watched_cves WHERE cve_id = ?", (cve_id,))
        conn.commit()
    finally:
        conn.close()


def get_watchlist_stats():
    conn = _get_db()
    try:
        total = conn.execute("SELECT COUNT(*) as c FROM watched_cves WHERE is_active = 1").fetchone()["c"]
        total_scans = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
        with_new = conn.execute("""
            SELECT COUNT(DISTINCT cve_id) as c FROM scan_history
            WHERE delta_hits > 0 AND id IN (SELECT MAX(id) FROM scan_history GROUP BY cve_id)
        """).fetchone()["c"]
        priorities = {}
        for row in conn.execute(
            "SELECT priority, COUNT(*) as c FROM watched_cves WHERE is_active = 1 GROUP BY priority"
        ):
            priorities[row["priority"]] = row["c"]
        stale_cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        needs_rescan = conn.execute("""
            SELECT COUNT(*) as c FROM watched_cves
            WHERE is_active = 1 AND (last_scanned IS NULL OR last_scanned < ?)
        """, (stale_cutoff,)).fetchone()["c"]
        return {
            "total_watched": total, "total_scans": total_scans,
            "with_new_activity": with_new, "needs_rescan": needs_rescan,
            "priorities": priorities,
        }
    finally:
        conn.close()


def get_change_log(limit=50):
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT sh.cve_id, sh.scanned_at, sh.total_hits, sh.delta_hits, sh.new_links,
                sh.risk_level, w.severity, w.product, w.vendor, w.priority
            FROM scan_history sh JOIN watched_cves w ON sh.cve_id = w.cve_id
            WHERE sh.delta_hits != 0 OR sh.id = (
                SELECT MIN(id) FROM scan_history WHERE cve_id = sh.cve_id
            )
            ORDER BY sh.scanned_at DESC LIMIT ?
        """, (limit,)).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["new_links"] = json.loads(d.get("new_links") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["new_links"] = []
            results.append(d)
        return results
    finally:
        conn.close()


def get_cves_due_for_rescan(max_age_hours=24):
    cutoff = (datetime.utcnow() - timedelta(hours=max_age_hours)).isoformat()
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT * FROM watched_cves
            WHERE is_active = 1 AND (last_scanned IS NULL OR last_scanned < ?)
            ORDER BY
                CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END,
                last_scanned ASC NULLS FIRST
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _calculate_trend(conn, cve_id):
    rows = conn.execute("""
        SELECT total_hits FROM scan_history
        WHERE cve_id = ? ORDER BY scanned_at DESC LIMIT 5
    """, (cve_id,)).fetchall()
    if len(rows) < 2:
        return "new"
    hits = [r["total_hits"] for r in rows]
    latest = hits[0]
    prior_avg = sum(hits[1:]) / len(hits[1:])
    if prior_avg == 0 and latest == 0:
        return "stable"
    elif prior_avg == 0 and latest > 0:
        return "rising"
    change_pct = ((latest - prior_avg) / max(prior_avg, 1)) * 100
    if change_pct > 20:
        return "rising"
    elif change_pct < -20:
        return "falling"
    return "stable"


def get_trend_data(cve_id, limit=30):
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT scanned_at, total_hits, delta_hits, epss_score, risk_level
            FROM scan_history WHERE cve_id = ?
            ORDER BY scanned_at ASC LIMIT ?
        """, (cve_id, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
