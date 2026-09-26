"""SQLite persistence layer.

The database stores five things:

* ``analyses``       : immutable analysis versions (request metadata + full result JSON)
* ``rules``          : one row per analyzed rule, for SQL-level filtering
* ``findings``       : one row per finding / minimal conflict pair, for SQL-level filtering
* ``active_pointer`` : singleton row (id=1) holding the currently published version
* ``active_history`` : append-only audit log of every successful pointer switch
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

# ``priority`` and ``covered`` are decimal TEXT, not INTEGER: the API accepts
# arbitrary non-negative JSON integers (and IPv6 address counts can exceed
# 64 bits), while an SQLite INTEGER column is signed 64-bit and binding a
# larger Python int raises OverflowError. Both are parsed back to int on read.
_RULES_TABLE_COLUMNS = """\
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_index    INTEGER NOT NULL,
    rule_id       TEXT NOT NULL,
    cidr          TEXT NOT NULL,
    ip_version    INTEGER NOT NULL,
    action        TEXT NOT NULL,
    priority      TEXT NOT NULL,
    source_tag    TEXT NOT NULL,
    role          TEXT NOT NULL,
    status        TEXT NOT NULL,
    covered       TEXT NOT NULL,
    has_conflict  INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, rule_index)\
"""

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS analyses (
    id               TEXT PRIMARY KEY,
    name             TEXT,
    ruleset_hash     TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    rule_count       INTEGER NOT NULL,
    result_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
{_RULES_TABLE_COLUMNS}
);

CREATE TABLE IF NOT EXISTS findings (
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    rule_id       TEXT,
    other_rule_id TEXT,
    behavioral    INTEGER NOT NULL,
    payload_json  TEXT NOT NULL,
    PRIMARY KEY (analysis_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_rules_analysis   ON rules(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
-- Unique so identical rule sets map to exactly one stored version. The
-- save_analysis write transaction serializes on this constraint; for a
-- database created before the constraint existed, init_db replaces the old
-- non-unique index with this one in place.
CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_hash ON analyses(ruleset_hash);

-- Singleton publication pointer: exactly one row (id = 1). It starts at
-- revision 0 with no published version and only points at saved analyses.
CREATE TABLE IF NOT EXISTS active_pointer (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    active_id    TEXT REFERENCES analyses(id),
    revision     INTEGER NOT NULL
);

-- Append-only audit trail. Every successful activate (including re-pointing
-- at the same version, which is still a distinct publication action) appends
-- one row with the previous/new version ids, the revision it produced and
-- when it happened. Rows are never updated or deleted; the foreign key uses
-- RESTRICT so a published analysis cannot be removed out from under the log.
CREATE TABLE IF NOT EXISTS active_history (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    revision      INTEGER NOT NULL,
    previous_id   TEXT REFERENCES analyses(id),
    active_id     TEXT NOT NULL REFERENCES analyses(id),
    activated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_active_history_revision ON active_history(revision);

INSERT OR IGNORE INTO active_pointer (id, active_id, revision) VALUES (1, NULL, 0);
"""

# In-memory cache of the configured path so tests can override it once.
_db_path: str | None = None
_path_lock = threading.Lock()


def get_db_path() -> str:
    global _db_path
    with _path_lock:
        if _db_path is None:
            configured = os.environ.get("PREFIX_DB_PATH")
            if configured:
                _db_path = configured
            else:
                # Prefer a user-writable data dir; fall back to a temp file
                # when /data exists but is not writable (common in containers
                # started without a volume).
                candidates = ["/data/prefix_policy.db"]
                import tempfile

                candidates.append(os.path.join(tempfile.gettempdir(), "prefix_policy.db"))
                chosen = candidates[-1]
                for path in candidates:
                    parent = os.path.dirname(path)
                    try:
                        os.makedirs(parent, exist_ok=True)
                        if os.access(parent, os.W_OK):
                            chosen = path
                            break
                    except OSError:
                        continue
                _db_path = chosen
        return _db_path


def set_db_path(path: str) -> None:
    """Override the database location (used by tests and at startup)."""
    global _db_path
    with _path_lock:
        _db_path = path


def _connect() -> sqlite3.Connection:
    path = get_db_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _ensure_unique_hash_index(conn: sqlite3.Connection) -> None:
    """Upgrade a legacy non-unique ``idx_analyses_hash`` to the unique version.

    Databases created before saves were deduplicated atomically carry the
    index as non-unique (``CREATE UNIQUE INDEX IF NOT EXISTS`` is a no-op on
    the already-existing name). DDL is transactional in SQLite, so dropping
    and recreating the index inside one transaction leaves the legacy index
    in place should duplicate hashes (possible only under the old racy save)
    make the unique creation fail — the existing data is never damaged.
    """
    row = conn.execute(
        "SELECT \"unique\" FROM pragma_index_list('analyses') WHERE name = 'idx_analyses_hash'"
    ).fetchone()
    if row is not None and row["unique"] == 1:
        return
    conn.execute("BEGIN")
    try:
        conn.execute("DROP INDEX IF EXISTS idx_analyses_hash")
        conn.execute("CREATE UNIQUE INDEX idx_analyses_hash ON analyses(ruleset_hash)")
    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK")
    else:
        conn.execute("COMMIT")


def _rules_priority_stored_as_text(conn: sqlite3.Connection) -> bool:
    """Whether the existing ``rules`` table keeps ``priority`` as TEXT.

    A non-empty declared type other than ``TEXT`` (databases created before
    large priorities were supported declare ``INTEGER``) means the column has
    NUMERIC/INTEGER affinity and storing a value above the signed 64-bit range
    fails; such a table needs the rebuild migration below.
    """
    cols = {
        row["name"]: (row["type"] or "").upper()
        for row in conn.execute("PRAGMA table_info(rules)")
    }
    return cols.get("priority") == "TEXT"


def _migrate_priority_to_text(conn: sqlite3.Connection) -> None:
    """Rebuild a legacy ``rules`` table whose ``priority`` is INTEGER as TEXT.

    SQLite cannot alter a column's type in place, so the table is rebuilt
    inside one transaction (DDL is transactional in SQLite): rename the old
    table, create the new one with decimal-TEXT ``priority`` (``CAST`` rewrites
    every existing value losslessly) and recreate the analysis index. The
    parent ``analyses`` rows are untouched and no table references ``rules``,
    but foreign keys are disabled for the connection so the rebuild itself
    never trips a constraint; should anything fail, the rollback restores the
    original table verbatim.
    """
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("BEGIN")
        try:
            # The index keeps its name when its table is renamed; drop it up
            # front so it can be recreated on the new table without a collision.
            conn.execute("DROP INDEX IF EXISTS idx_rules_analysis")
            conn.execute("ALTER TABLE rules RENAME TO rules_legacy_priority")
            conn.execute(f"CREATE TABLE rules (\n{_RULES_TABLE_COLUMNS}\n)")
            conn.execute(
                """
                INSERT INTO rules
                    (analysis_id, rule_index, rule_id, cidr, ip_version, action, priority,
                     source_tag, role, status, covered, has_conflict)
                SELECT analysis_id, rule_index, rule_id, cidr, ip_version, action,
                       CAST(priority AS TEXT), source_tag, role, status, covered, has_conflict
                FROM rules_legacy_priority
                """
            )
            conn.execute("CREATE INDEX idx_rules_analysis ON rules(analysis_id)")
            conn.execute("DROP TABLE rules_legacy_priority")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        # Restore the connection default (no-op once the transaction ended).
        conn.execute("PRAGMA foreign_keys=ON")


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        _ensure_unique_hash_index(conn)
        # Upgrade databases whose rules.priority predates TEXT storage, so
        # legal priorities beyond the signed 64-bit SQLite INTEGER range can be
        # saved without an OverflowError.
        rules_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rules'"
        ).fetchone()
        if rules_exists is not None and not _rules_priority_stored_as_text(conn):
            _migrate_priority_to_text(conn)


def reset_db(path: str | None = None) -> None:
    """Drop and recreate all tables (tests only)."""
    if path is not None:
        set_db_path(path)
    with _connect() as conn:
        conn.executescript(
            "DROP TABLE IF EXISTS active_history; DROP TABLE IF EXISTS active_pointer; "
            "DROP TABLE IF EXISTS findings; DROP TABLE IF EXISTS rules; DROP TABLE IF EXISTS analyses;"
        )
        conn.executescript(_SCHEMA)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_analysis(
    analysis_id: str,
    name: str | None,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Persist a complete analysis, atomically reusing an identical stored version.

    Returns the stored version metadata: ``{"id", "name", "created_at",
    "reused"}``. Concurrent submissions of the same ruleset hash are
    serialized inside one ``BEGIN IMMEDIATE`` write transaction, so the
    check-then-insert race (two requests both seeing no row and then colliding
    on the unique constraints) cannot happen: exactly one request performs
    the insert — one ``analyses`` row plus that version's rules and findings —
    and every other request reads that row back. The unique index on
    ``ruleset_hash`` (and the primary key on ``id``) remain the final
    backstop. Reused versions keep the *first* save's name and created_at;
    the duplicate request's name is ignored.
    """
    ruleset_hash = result["ruleset_hash"]
    conn = _connect()
    # An unmanaged transaction: BEGIN IMMEDIATE takes the write lock up front
    # so two competing saves cannot both observe "no existing row".
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT id, name, created_at FROM analyses WHERE ruleset_hash = ?",
            (ruleset_hash,),
        ).fetchone()
        if existing is not None:
            conn.execute("COMMIT")
            return {
                "id": existing["id"],
                "name": existing["name"],
                "created_at": existing["created_at"],
                "reused": True,
            }

        created_at = utc_now_iso()
        conn.execute(
            """INSERT INTO analyses
               (id, name, ruleset_hash, analyzer_version, created_at, rule_count, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis_id,
                name,
                ruleset_hash,
                result["analyzer_version"],
                created_at,
                result["summary"]["rule_count"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        conn.executemany(
            """INSERT INTO rules
               (analysis_id, rule_index, rule_id, cidr, ip_version, action, priority,
                source_tag, role, status, covered, has_conflict)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id,
                    r["index"],
                    r["rule_id"],
                    r["cidr"],
                    r["ip_version"],
                    r["action"],
                    str(r["priority"]),  # TEXT: priorities may exceed SQLite's 64-bit INTEGER
                    r["source_tag"],
                    r["role"],
                    r["status"],
                    str(r["covered"]),  # IPv6 counts exceed SQLite INTEGER range
                    1 if r["has_conflict"] else 0,
                )
                for r in result["rules"]
            ],
        )
        finding_rows = []
        seq = 0
        for f in result["findings"]:
            finding_rows.append(
                (
                    analysis_id,
                    seq,
                    f["type"],
                    f["severity"],
                    f.get("rule_id"),
                    f.get("other_rule_id"),
                    1 if f.get("behavioral") else 0,
                    json.dumps(f, ensure_ascii=False),
                )
            )
            seq += 1
        conn.executemany(
            """INSERT INTO findings
               (analysis_id, seq, kind, severity, rule_id, other_rule_id, behavioral, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            finding_rows,
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        raise
    conn.close()

    return {
        "id": analysis_id,
        "name": name,
        "created_at": created_at,
        "reused": False,
    }


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json, created_at, name FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["id"] = analysis_id
    result["name"] = row["name"]
    result["created_at"] = row["created_at"]
    return result


def list_analyses(limit: int = 50, offset: int = 0) -> tuple[int, list[dict[str, Any]]]:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        rows = conn.execute(
            """SELECT id, name, ruleset_hash, analyzer_version, created_at, rule_count
               FROM analyses ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return total, [dict(r) for r in rows]


def query_rules(
    analysis_id: str,
    status: str | None = None,
    action: str | None = None,
    ip_version: int | None = None,
) -> list[dict[str, Any]] | None:
    """Return stored rule rows for an analysis, optionally filtered.

    Returns ``None`` when the analysis does not exist.
    """
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            return None
        sql = "SELECT * FROM rules WHERE analysis_id = ?"
        params: list[Any] = [analysis_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if action:
            sql += " AND action = ?"
            params.append(action)
        if ip_version is not None:
            sql += " AND ip_version = ?"
            params.append(ip_version)
        sql += " ORDER BY rule_index"
        rows = conn.execute(sql, params).fetchall()
    result_rows = [dict(r) for r in rows]
    for row in result_rows:
        # Stored as decimal TEXT to accommodate values outside INTEGER range:
        # priorities may exceed 64 bits and IPv6 address counts always can.
        row["priority"] = int(row["priority"])
        row["covered"] = int(row["covered"])
        row["has_conflict"] = bool(row["has_conflict"])
    return result_rows


def query_findings(
    analysis_id: str,
    severity: str | None = None,
    behavioral_only: bool = False,
) -> list[dict[str, Any]] | None:
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            return None
        sql = "SELECT * FROM findings WHERE analysis_id = ?"
        params: list[Any] = [analysis_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if behavioral_only:
            sql += " AND behavioral = 1"
        sql += " ORDER BY seq"
        rows = conn.execute(sql, params).fetchall()
    return [
        {
            "seq": r["seq"],
            "kind": r["kind"],
            "severity": r["severity"],
            "rule_id": r["rule_id"],
            "other_rule_id": r["other_rule_id"],
            "behavioral": bool(r["behavioral"]),
            "detail": json.loads(r["payload_json"]),
        }
        for r in rows
    ]


class RevisionConflict(Exception):
    """Raised when an optimistic-concurrency activation loses the revision race.

    Carries the pointer state as it currently stands in the database so the
    API can return it to the caller.
    """

    def __init__(self, current: dict[str, Any]):
        super().__init__(
            f"pointer revision {current['revision']} does not match expected revision"
        )
        self.current = current


def get_active() -> dict[str, Any]:
    """Return the current publication pointer (singleton row id = 1)."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT active_id, revision FROM active_pointer WHERE id = 1"
        ).fetchone()
    return {"active_id": row["active_id"], "revision": row["revision"]}


def activate_pointer(analysis_id: str, expected_revision: int) -> dict[str, Any]:
    """Publish ``analysis_id`` when the pointer still sits at ``expected_revision``.

    The revision check, pointer update, revision increment and history insert
    happen in one immediate (write) SQLite transaction, so concurrent publishes
    are serialized: exactly one request per revision value can win, and a loser
    gets :class:`RevisionConflict` carrying the current state. A successful
    switch always bumps the revision and appends an audit row, even when the new
    target equals the already published version.

    Callers must verify beforehand that ``analysis_id`` is a saved analysis;
    the foreign key on ``active_pointer.active_id`` is the final backstop.
    """
    conn = _connect()
    # An unmanaged transaction: BEGIN IMMEDIATE takes the write lock up front
    # so two competing activations cannot both observe the same revision.
    conn.isolation_level = None
    activated_at = utc_now_iso()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT active_id, revision FROM active_pointer WHERE id = 1"
        ).fetchone()
        current_revision = row["revision"]
        if current_revision != expected_revision:
            conn.execute("ROLLBACK")
            raise RevisionConflict(
                {"active_id": row["active_id"], "revision": current_revision}
            )

        new_revision = current_revision + 1
        conn.execute(
            "UPDATE active_pointer SET active_id = ?, revision = ? WHERE id = 1",
            (analysis_id, new_revision),
        )
        cur = conn.execute(
            """INSERT INTO active_history
               (revision, previous_id, active_id, activated_at)
               VALUES (?, ?, ?, ?)""",
            (new_revision, row["active_id"], analysis_id, activated_at),
        )
        history_seq = cur.lastrowid
        conn.execute("COMMIT")
    except Exception:
        # ROLLBACK is a no-op once the conflict path has already rolled back;
        # ignore that and let the original exception propagate.
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        raise
    conn.close()

    return {
        "active_id": analysis_id,
        "revision": new_revision,
        "activated_at": activated_at,
        "history_seq": history_seq,
        "previous": {"active_id": row["active_id"], "revision": current_revision},
    }


def list_active_history(limit: int = 50, offset: int = 0) -> tuple[int, list[dict[str, Any]]]:
    """Read-only audit log of successful switches, newest first."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM active_history").fetchone()["c"]
        rows = conn.execute(
            """SELECT seq, revision, previous_id, active_id, activated_at
               FROM active_history ORDER BY seq DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return total, [dict(r) for r in rows]
