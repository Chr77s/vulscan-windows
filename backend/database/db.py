"""
Couche SQLite — persistance des scans côté backend.

Schéma :
  scans     : id, url, started_at, finished_at, total, score, risk_label
  findings  : id, scan_id (FK), payload JSON complet de la vuln

Le payload JSON permet d'évoluer sans migration : on stocke tout, on requête
sur les colonnes indexées.
"""
from __future__ import annotations
import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Optional
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnscan.db")
_lock = threading.Lock()  # SQLite est thread-safe en mode WAL, mais on protège côté Python


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Crée les tables si elles n'existent pas."""
    with _lock, _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id            TEXT PRIMARY KEY,
                url           TEXT NOT NULL,
                started_at    INTEGER NOT NULL,
                finished_at   INTEGER,
                total         INTEGER DEFAULT 0,
                critical      INTEGER DEFAULT 0,
                high          INTEGER DEFAULT 0,
                medium        INTEGER DEFAULT 0,
                low           INTEGER DEFAULT 0,
                info          INTEGER DEFAULT 0,
                score         INTEGER DEFAULT 0,
                risk_label    TEXT,
                payload       TEXT,
                created_at    INTEGER DEFAULT (strftime('%s', 'now') * 1000)
            );
            CREATE INDEX IF NOT EXISTS idx_scans_url        ON scans(url);
            CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);

            CREATE TABLE IF NOT EXISTS findings (
                id            TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                type          TEXT NOT NULL,
                severity      TEXT NOT NULL,
                confidence    INTEGER,
                cvss_base     REAL,
                cwe_id        TEXT,
                owasp_id      TEXT,
                title         TEXT,
                parameter     TEXT,
                url           TEXT,
                payload       TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(type);
        """)


# -----------------------------------------------------------------
# Aide : calcul rapide des stats
# -----------------------------------------------------------------
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

def _stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    score = 0
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
        score += SEVERITY_WEIGHT.get(sev, 0)
    if   score == 0:  risk = "Aucun risque"
    elif score < 5:   risk = "Risque faible"
    elif score < 15:  risk = "Risque modéré"
    elif score < 35:  risk = "Risque élevé"
    else:             risk = "Risque critique"
    return {"counts": counts, "score": score, "risk_label": risk}


# -----------------------------------------------------------------
# API
# -----------------------------------------------------------------
def save_scan(scan: Dict[str, Any]) -> str:
    """Insère ou remplace un scan complet."""
    findings = scan.get("vulnerabilities", []) or []
    stats = _stats(findings)

    with _lock, _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO scans
            (id, url, started_at, finished_at, total, critical, high, medium, low, info, score, risk_label, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan["id"], scan.get("url", ""),
            scan.get("startedAt", int(time.time() * 1000)),
            scan.get("finishedAt"),
            len(findings),
            stats["counts"]["critical"], stats["counts"]["high"],
            stats["counts"]["medium"],   stats["counts"]["low"],
            stats["counts"]["info"],
            stats["score"], stats["risk_label"],
            json.dumps(scan, ensure_ascii=False),
        ))
        # Nettoyer les anciens findings de ce scan puis ré-insérer
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan["id"],))
        for f in findings:
            conn.execute("""
                INSERT OR REPLACE INTO findings
                (id, scan_id, type, severity, confidence, cvss_base, cwe_id, owasp_id, title, parameter, url, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.get("id", ""), scan["id"],
                f.get("type", ""), f.get("severity", "info"),
                f.get("confidence"),
                f.get("cvssBase") or f.get("cvss_base"),
                (f.get("cwe") or {}).get("id") if isinstance(f.get("cwe"), dict) else f.get("cwe_id"),
                (f.get("owasp") or {}).get("id") if isinstance(f.get("owasp"), dict) else f.get("owasp_id"),
                f.get("title", ""), f.get("parameter", ""),
                f.get("url", ""),
                json.dumps(f, ensure_ascii=False),
            ))
    return scan["id"]


def list_scans(limit: int = 50, url_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock, _connect() as conn:
        if url_filter:
            rows = conn.execute("""
                SELECT id, url, started_at, finished_at, total, critical, high, medium, low, info, score, risk_label
                FROM scans WHERE url LIKE ? ORDER BY started_at DESC LIMIT ?
            """, (f"%{url_filter}%", limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, url, started_at, finished_at, total, critical, high, medium, low, info, score, risk_label
                FROM scans ORDER BY started_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["payload"])


def delete_scan(scan_id: str) -> bool:
    with _lock, _connect() as conn:
        c = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return c.rowcount > 0


def diff_scans(scan_a_id: str, scan_b_id: str) -> Dict[str, Any]:
    """
    Compare 2 scans et retourne :
      added    : findings dans B mais pas dans A
      removed  : findings dans A mais pas dans B
      changed  : même type+parameter mais sévérité ou score différents
      stable   : présents dans les 2 sans changement
    Clé d'identification : (type, parameter, url)
    """
    a = get_scan(scan_a_id) or {}
    b = get_scan(scan_b_id) or {}
    if not a or not b:
        return {"error": "scan introuvable"}

    def key(f):
        return (f.get("type", ""), (f.get("parameter") or "")[:80], f.get("url", ""))

    a_idx = {key(f): f for f in a.get("vulnerabilities", [])}
    b_idx = {key(f): f for f in b.get("vulnerabilities", [])}

    a_keys = set(a_idx.keys())
    b_keys = set(b_idx.keys())

    added   = [b_idx[k] for k in b_keys - a_keys]
    removed = [a_idx[k] for k in a_keys - b_keys]

    changed = []
    stable = []
    for k in a_keys & b_keys:
        fa, fb = a_idx[k], b_idx[k]
        if fa.get("severity") != fb.get("severity") or fa.get("cvssBase") != fb.get("cvssBase"):
            changed.append({"key": k, "before": fa, "after": fb})
        else:
            stable.append(fb)

    return {
        "scan_a": {"id": scan_a_id, "url": a.get("url"), "total": len(a.get("vulnerabilities", []))},
        "scan_b": {"id": scan_b_id, "url": b.get("url"), "total": len(b.get("vulnerabilities", []))},
        "added": added,
        "removed": removed,
        "changed": changed,
        "stable_count": len(stable),
    }
