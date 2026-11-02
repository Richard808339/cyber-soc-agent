"""Stockage SQLite du tableau de bord : snapshots, alertes, bilans, journal d'ingestion."""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("SOC_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc.db"))
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    payload      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    fingerprint TEXT PRIMARY KEY,
    ts          TEXT,
    agent       TEXT,
    rule_id     TEXT,
    level       INTEGER,
    description TEXT,
    groups      TEXT,
    mitre_ids   TEXT,
    srcip       TEXT,
    playbook    TEXT,
    state       TEXT DEFAULT 'nouveau'
);

CREATE TABLE IF NOT EXISTS summaries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at TEXT NOT NULL,
    engine       TEXT NOT NULL,
    model        TEXT,
    text         TEXT NOT NULL,
    metrics      TEXT
);

CREATE TABLE IF NOT EXISTS ingest_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    ok      INTEGER NOT NULL,
    bytes   INTEGER,
    source  TEXT,
    detail  TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);

CREATE TABLE IF NOT EXISTS notifications (
    key     TEXT PRIMARY KEY,
    sent_at TEXT NOT NULL
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with _lock, connect() as conn:
        conn.executescript(SCHEMA)


def save_snapshot(payload):
    blob = json.dumps(payload, ensure_ascii=False, default=str)
    with _lock, connect() as conn:
        conn.execute(
            "INSERT INTO snapshots (collected_at, received_at, payload) VALUES (?, datetime('now'), ?)",
            (str(payload.get("collected_at") or ""), blob),
        )
        # On garde un historique court : 500 snapshots suffisent pour la tendance.
        conn.execute(
            "DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT 500)"
        )
    return len(blob)


def latest_snapshot():
    with connect() as conn:
        row = conn.execute(
            "SELECT payload, received_at FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    data = json.loads(row["payload"])
    data["_received_at"] = row["received_at"]
    return data


def list_snapshots(limit=30):
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, collected_at, received_at FROM snapshots ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def save_alerts(alerts):
    """Upsert par empreinte : pas de doublon si le collecteur repousse les memes alertes."""
    import hashlib

    new = 0
    with _lock, connect() as conn:
        for a in alerts:
            fp = a.get("fingerprint") or hashlib.sha1(
                ("%s|%s|%s|%s" % (a.get("ts"), a.get("agent"), a.get("rule_id"), a.get("description"))).encode("utf-8")
            ).hexdigest()
            cur = conn.execute(
                "INSERT OR IGNORE INTO alerts (fingerprint, ts, agent, rule_id, level, description, groups, mitre_ids, srcip, playbook) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    fp, a.get("ts"), a.get("agent"), str(a.get("rule_id") or ""),
                    int(a.get("level") or 0), a.get("description"),
                    json.dumps(a.get("groups") or [], ensure_ascii=False),
                    json.dumps(a.get("mitre_ids") or [], ensure_ascii=False),
                    a.get("srcip"), a.get("playbook"),
                ),
            )
            new += cur.rowcount
    return new


def query_alerts(level_min=None, agent=None, playbook=None, limit=100):
    sql = "SELECT * FROM alerts WHERE 1=1"
    args = []
    if level_min is not None:
        sql += " AND level >= ?"
        args.append(int(level_min))
    if agent:
        sql += " AND agent = ?"
        args.append(agent)
    if playbook:
        sql += " AND playbook = ?"
        args.append(playbook)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    with connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["groups"] = json.loads(d.get("groups") or "[]")
        d["mitre_ids"] = json.loads(d.get("mitre_ids") or "[]")
        out.append(d)
    return out


def alert_stats():
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        by_level = conn.execute(
            "SELECT level, COUNT(*) c FROM alerts GROUP BY level ORDER BY level DESC"
        ).fetchall()
        by_playbook = conn.execute(
            "SELECT playbook, COUNT(*) c FROM alerts WHERE playbook IS NOT NULL GROUP BY playbook ORDER BY c DESC"
        ).fetchall()
    return {
        "total": total,
        "by_level": {str(r["level"]): r["c"] for r in by_level},
        "by_playbook": {r["playbook"]: r["c"] for r in by_playbook},
    }


def save_summary(summary):
    with _lock, connect() as conn:
        conn.execute(
            "INSERT INTO summaries (generated_at, engine, model, text, metrics) VALUES (?,?,?,?,?)",
            (
                summary["generated_at"], summary["engine"], summary.get("model"),
                summary["text"], json.dumps(summary.get("metrics") or {}, ensure_ascii=False),
            ),
        )
        conn.execute(
            "DELETE FROM summaries WHERE id NOT IN (SELECT id FROM summaries ORDER BY id DESC LIMIT 100)"
        )
    return summary


def latest_summary():
    with connect() as conn:
        row = conn.execute("SELECT * FROM summaries ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    d = dict(row)
    d["metrics"] = json.loads(d.get("metrics") or "{}")
    return d


def log_ingest(ok, nbytes=0, source="", detail=""):
    with _lock, connect() as conn:
        conn.execute(
            "INSERT INTO ingest_log (ts, ok, bytes, source, detail) VALUES (datetime('now'),?,?,?,?)",
            (1 if ok else 0, nbytes, source, detail[:300]),
        )


def recently_notified(key, cooldown_seconds):
    """Vrai si la meme notification a deja ete envoyee il y a moins de N secondes."""
    with connect() as conn:
        row = conn.execute("SELECT sent_at FROM notifications WHERE key = ?", (key,)).fetchone()
        if not row:
            return False
        prev = conn.execute(
            "SELECT (strftime('%s','now') - strftime('%s', ?)) AS dt", (row["sent_at"],)
        ).fetchone()
    try:
        return int(prev["dt"]) < int(cooldown_seconds)
    except Exception:
        return False


def mark_notified(key):
    with _lock, connect() as conn:
        conn.execute(
            "INSERT INTO notifications (key, sent_at) VALUES (?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET sent_at = datetime('now')",
            (key,),
        )


def ingest_history(limit=10):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM ingest_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init()
    print("Base initialisee :", DB_PATH)
