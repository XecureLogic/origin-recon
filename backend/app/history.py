"""Scan-history persistence (SQLite, stdlib only, thread-safe).

Every scan is stored so analysts can recall prior results instead of re-running.
The DB lives next to the backend (origin-recon.db) and is created on first use.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

_DB_PATH = Path(__file__).resolve().parents[1] / "origin-recon.db"
_LOCK = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL,
                verdict     TEXT,
                edge_masked TEXT,
                created_at  TEXT,
                host_count  INTEGER DEFAULT 0,
                known_bad   INTEGER DEFAULT 0,
                payload     TEXT NOT NULL
            )
            """
        )
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        _conn.commit()
    return _conn


def _as_dict(scan) -> dict:
    if hasattr(scan, "model_dump"):
        return scan.model_dump()
    if isinstance(scan, dict):
        return scan
    raise TypeError("scan must be a pydantic model or dict")


def save_scan(scan) -> int:
    p = _as_dict(scan)
    hosts = (p.get("ips") or [])
    cands = (p.get("origin_candidates") or [])
    known_bad = sum(1 for x in hosts + cands if x.get("reputation"))
    created = p.get("created_at") or dt.datetime.now(dt.timezone.utc).isoformat()
    with _LOCK:
        c = _connect()
        cur = c.execute(
            "INSERT INTO scans (domain, verdict, edge_masked, created_at, host_count, known_bad, payload)"
            " VALUES (?,?,?,?,?,?,?)",
            (p.get("domain"), p.get("verdict"), p.get("edge_masked"),
             created, len(hosts), known_bad, json.dumps(p)),
        )
        c.commit()
        return int(cur.lastrowid)


def list_scans(limit: int = 50) -> list[dict]:
    with _LOCK:
        c = _connect()
        rows = c.execute(
            "SELECT id, domain, verdict, edge_masked, created_at, host_count, known_bad"
            " FROM scans ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> Optional[dict]:
    with _LOCK:
        c = _connect()
        row = c.execute("SELECT payload FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
    return json.loads(row["payload"]) if row else None


def latest_for_domain(domain: str) -> Optional[dict]:
    with _LOCK:
        c = _connect()
        row = c.execute(
            "SELECT payload FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,)
        ).fetchone()
    return json.loads(row["payload"]) if row else None


def delete_scan(scan_id: int) -> bool:
    with _LOCK:
        c = _connect()
        cur = c.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
        c.commit()
        return cur.rowcount > 0
