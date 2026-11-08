"""SQLite findings store with the three statuses from the plan.

OPEN            exposure currently believed present
FIXED_VERIFIED  a re-scan confirmed it is gone (only verify.py sets this)
ACCEPTED_RISK   a person decided to live with it (reason required)
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path

from .knowledge import KnowledgeBase, finding_key
from .scanners.base import Finding

OPEN = "OPEN"
FIXED = "FIXED_VERIFIED"
ACCEPTED = "ACCEPTED_RISK"
STATUSES = (OPEN, FIXED, ACCEPTED)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    verified_at TEXT,
    note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    key TEXT,
    event TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    target TEXT NOT NULL,
    engine TEXT NOT NULL,
    found INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ttc_external REAL,
    ttc_internal REAL,
    chain_length INTEGER NOT NULL DEFAULT 0,
    counts TEXT NOT NULL,
    records TEXT NOT NULL,
    path TEXT NOT NULL
);
"""

_FIELDS = {f.name for f in fields(Finding)}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def finding_from_dict(d: dict) -> Finding:
    return Finding(**{k: v for k, v in d.items() if k in _FIELDS})


class Store:
    def __init__(self, path: str | Path = "data/fallline.db"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._mem = sqlite3.connect(":memory:", check_same_thread=False) if self.path == ":memory:" else None
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = self._mem or sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self._mem is None:
                conn.close()

    # -- writing ----------------------------------------------------------
    def ingest(self, findings: list[Finding], kb: KnowledgeBase, target: str = "", engine: str = "") -> dict:
        """Add scan results. Never marks anything fixed: only verify does that."""
        now = _now()
        counts = {"new": 0, "seen": 0, "reopened": 0}
        with self._conn() as c:
            for f in findings:
                rule = kb.classify(f)
                key = finding_key(f, rule.id if rule else "none")
                row = c.execute("SELECT status FROM findings WHERE key=?", (key,)).fetchone()
                data = json.dumps(f.to_dict())
                if row is None:
                    c.execute(
                        "INSERT INTO findings VALUES (?,?,?,?,?,?,NULL,'')",
                        (key, rule.id if rule else "none", data, OPEN, now, now),
                    )
                    c.execute(
                        "INSERT INTO events(time,key,event,detail) VALUES (?,?,?,?)", (now, key, "found", "first seen")
                    )
                    counts["new"] += 1
                elif row["status"] == FIXED:
                    c.execute(
                        "UPDATE findings SET data=?, status=?, last_seen=?, verified_at=NULL WHERE key=?",
                        (data, OPEN, now, key),
                    )
                    c.execute(
                        "INSERT INTO events(time,key,event,detail) VALUES (?,?,?,?)",
                        (now, key, "reopened", "seen again after being verified fixed"),
                    )
                    counts["reopened"] += 1
                else:
                    c.execute("UPDATE findings SET data=?, last_seen=? WHERE key=?", (data, now, key))
                    counts["seen"] += 1
            if target:
                c.execute(
                    "INSERT INTO scans(time,target,engine,found) VALUES (?,?,?,?)", (now, target, engine, len(findings))
                )
        return counts

    def set_status(self, key: str, status: str, note: str = "", event: str = "") -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status}")
        now = _now()
        with self._conn() as c:
            if c.execute("SELECT 1 FROM findings WHERE key=?", (key,)).fetchone() is None:
                raise KeyError(key)
            c.execute(
                "UPDATE findings SET status=?, note=?, verified_at=? WHERE key=?",
                (status, note, now if status == FIXED else None, key),
            )
            c.execute(
                "INSERT INTO events(time,key,event,detail) VALUES (?,?,?,?)", (now, key, event or status.lower(), note)
            )

    def log_event(self, key: str | None, event: str, detail: str = "") -> None:
        with self._conn() as c:
            c.execute("INSERT INTO events(time,key,event,detail) VALUES (?,?,?,?)", (_now(), key, event, detail))

    def save_snapshot(
        self,
        name: str,
        ttc_external: float | None,
        ttc_internal: float | None,
        chain_length: int,
        counts: dict,
        records: list[dict],
        path: list[dict],
    ) -> dict:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Snapshot name cannot be empty")
        now = _now()
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO snapshots(name,created_at,ttc_external,ttc_internal,chain_length,counts,records,path) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    clean_name,
                    now,
                    ttc_external,
                    ttc_internal,
                    chain_length,
                    json.dumps(counts),
                    json.dumps(records),
                    json.dumps(path),
                ),
            )
            snap_id = int(cur.lastrowid)
            c.execute(
                "INSERT INTO events(time,key,event,detail) VALUES (?,?,?,?)",
                (now, None, "snapshot_saved", f"{snap_id}: {clean_name}"),
            )
        return {
            "id": snap_id,
            "name": clean_name,
            "created_at": now,
            "ttc_external": ttc_external,
            "ttc_internal": ttc_internal,
            "chain_length": chain_length,
            "counts": counts,
        }

    # -- reading ----------------------------------------------------------
    def _row(self, r: sqlite3.Row) -> dict:
        return {
            "key": r["key"],
            "rule_id": r["rule_id"],
            "status": r["status"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "verified_at": r["verified_at"],
            "note": r["note"],
            "finding": finding_from_dict(json.loads(r["data"])),
        }

    def get(self, key: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM findings WHERE key=?", (key,)).fetchone()
        return self._row(r) if r else None

    def all(self, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM findings", ()
        if status:
            q, args = q + " WHERE status=?", (status,)
        with self._conn() as c:
            return [self._row(r) for r in c.execute(q + " ORDER BY key", args)]

    def open_items(self) -> list[tuple[str, Finding]]:
        return [(r["key"], r["finding"]) for r in self.all(OPEN) if r["rule_id"] != "none"]

    def events(self, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            return [
                dict(r)
                for r in c.execute("SELECT time,key,event,detail FROM events ORDER BY id DESC LIMIT ?", (limit,))
            ]

    def list_snapshots(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id,name,created_at,ttc_external,ttc_internal,chain_length,counts FROM snapshots ORDER BY id ASC"
            ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "created_at": r["created_at"],
                "ttc_external": r["ttc_external"],
                "ttc_internal": r["ttc_internal"],
                "chain_length": r["chain_length"],
                "counts": json.loads(r["counts"]),
            }
            for r in rows
        ]

    def get_snapshot(self, snapshot_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if r is None:
            return None
        return {
            "id": r["id"],
            "name": r["name"],
            "created_at": r["created_at"],
            "ttc_external": r["ttc_external"],
            "ttc_internal": r["ttc_internal"],
            "chain_length": r["chain_length"],
            "counts": json.loads(r["counts"]),
            "records": json.loads(r["records"]),
            "path": json.loads(r["path"]),
        }
