"""Tests for the legacy duplicate-ruleset_hash migration at startup.

Databases written before saves were deduplicated atomically may hold several
``analyses`` rows for one ``ruleset_hash`` and carry ``idx_analyses_hash`` as
a non-unique index. ``init_db`` must collapse the duplicates (keeping the
first save by ``created_at``/``id``), rewrite the publication pointer and
audit history onto the kept version, delete the dropped versions'
rules/findings/analyses rows and create the unique index — all in one
transaction, so a failure rolls everything back and makes startup fail.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db
from app.analyzer import analyze_rules

# The current schema shape, except that idx_analyses_hash is the legacy
# NON-unique index (and rules.priority is already TEXT, so only the hash
# migration runs).
_LEGACY_SCHEMA = """
CREATE TABLE analyses (
    id TEXT PRIMARY KEY, name TEXT, ruleset_hash TEXT NOT NULL,
    analyzer_version TEXT NOT NULL, created_at TEXT NOT NULL,
    rule_count INTEGER NOT NULL, result_json TEXT NOT NULL
);
CREATE TABLE rules (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_index INTEGER NOT NULL, rule_id TEXT NOT NULL, cidr TEXT NOT NULL,
    ip_version INTEGER NOT NULL, action TEXT NOT NULL, priority TEXT NOT NULL,
    source_tag TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL,
    covered TEXT NOT NULL, has_conflict INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, rule_index)
);
CREATE TABLE findings (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
    rule_id TEXT, other_rule_id TEXT, behavioral INTEGER NOT NULL,
    payload_json TEXT NOT NULL, PRIMARY KEY (analysis_id, seq)
);
CREATE INDEX idx_rules_analysis ON rules(analysis_id);
CREATE INDEX idx_findings_analysis ON findings(analysis_id);
CREATE INDEX idx_analyses_hash ON analyses(ruleset_hash);
CREATE TABLE active_pointer (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active_id TEXT REFERENCES analyses(id), revision INTEGER NOT NULL
);
CREATE TABLE active_history (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, revision INTEGER NOT NULL,
    previous_id TEXT REFERENCES analyses(id),
    active_id TEXT NOT NULL REFERENCES analyses(id), activated_at TEXT NOT NULL
);
CREATE INDEX idx_active_history_revision ON active_history(revision);
INSERT OR IGNORE INTO active_pointer (id, active_id, revision) VALUES (1, NULL, 0);
"""

_RULESET = [
    {"cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
    {"cidr": "10.1.0.0/16", "action": "deny", "priority": 50},
]

KEEPER = "an_00000000000000a1"  # earliest created_at, lowest id on the tie
DROPPED_LATER = "an_00000000000000b2"  # same hash, later created_at
DROPPED_TIE = "an_00000000000000c3"  # same hash, same created_at, higher id
SOLO = "an_00000000000000d4"  # unique hash: must remain untouched

_T1 = "2026-01-01T00:00:00Z"
_T2 = "2026-01-02T00:00:00Z"
_T3 = "2026-01-03T00:00:00Z"


def _insert_analysis(conn, analysis_id, ruleset_hash, name, created_at, result_json):
    conn.execute(
        "INSERT INTO analyses VALUES (?,?,?,?,?,?,?)",
        (analysis_id, name, ruleset_hash, "1.0.0", created_at, 2, result_json),
    )


def _insert_rule_row(conn, analysis_id, rule_index=0, rule_id="r1"):
    conn.execute(
        "INSERT INTO rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (analysis_id, rule_index, rule_id, "10.0.0.0/8", 4, "permit", "100",
         "default", "winner", "partial", "16777216", 0),
    )


def _insert_finding_row(conn, analysis_id, seq=0):
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
        (analysis_id, seq, "shadowed_rule", "info", "r1", None, 0, "{}"),
    )


def _seed_legacy_db(path: str) -> dict:
    """Build a legacy database with three versions of one ruleset hash."""
    result = analyze_rules([dict(r) for r in _RULESET])
    dup_hash = result["ruleset_hash"]
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_LEGACY_SCHEMA)
        # Three versions of the same hash, inserted out of order: the keeper
        # is the earliest created_at, ties broken by the lowest id.
        _insert_analysis(conn, DROPPED_LATER, dup_hash, "dup-later", _T2, "{}")
        _insert_analysis(conn, DROPPED_TIE, dup_hash, "dup-tie", _T1, "{}")
        _insert_analysis(
            conn, KEEPER, dup_hash, "first-save", _T1,
            json.dumps(result, ensure_ascii=False),
        )
        _insert_analysis(conn, SOLO, "h_solo", "solo", _T3, "{}")
        for analysis_id in (KEEPER, DROPPED_LATER, DROPPED_TIE, SOLO):
            _insert_rule_row(conn, analysis_id)
            _insert_finding_row(conn, analysis_id)
        # The publication pointer and the audit log reference duplicates that
        # the migration will drop.
        conn.execute(
            "UPDATE active_pointer SET active_id = ?, revision = 3 WHERE id = 1",
            (DROPPED_LATER,),
        )
        conn.executemany(
            "INSERT INTO active_history (revision, previous_id, active_id, activated_at)"
            " VALUES (?,?,?,?)",
            [
                (1, None, SOLO, "2026-01-04T00:00:00Z"),
                (2, SOLO, DROPPED_LATER, "2026-01-05T00:00:00Z"),
                (3, DROPPED_LATER, DROPPED_TIE, "2026-01-06T00:00:00Z"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return result


@pytest.fixture()
def legacy_db():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-duphash-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    result = _seed_legacy_db(path)
    db.set_db_path(path)
    yield path, result
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _hash_index_is_unique(conn) -> bool:
    row = conn.execute(
        "SELECT \"unique\" FROM pragma_index_list('analyses')"
        " WHERE name = 'idx_analyses_hash'"
    ).fetchone()
    return row is not None and row["unique"] == 1


def _ids(conn, table: str, column: str = "analysis_id") -> set[str]:
    return {r[0] for r in conn.execute(f"SELECT DISTINCT {column} FROM {table}")}


def test_duplicate_hash_versions_are_collapsed_at_init(legacy_db) -> None:
    path, _result = legacy_db
    db.init_db()

    with db._connect() as conn:
        assert _hash_index_is_unique(conn)

        # Only the keeper (earliest created_at, lowest id) and the untouched
        # solo version remain; the dropped versions' rows are gone everywhere.
        assert _ids(conn, "analyses", "id") == {KEEPER, SOLO}
        assert _ids(conn, "rules") == {KEEPER, SOLO}
        assert _ids(conn, "findings") == {KEEPER, SOLO}

        # The keeper's own metadata is untouched.
        keeper = conn.execute(
            "SELECT name, created_at FROM analyses WHERE id = ?", (KEEPER,)
        ).fetchone()
        assert (keeper["name"], keeper["created_at"]) == ("first-save", _T1)

        # The pointer now references the keeper; the revision is unchanged.
        pointer = conn.execute(
            "SELECT active_id, revision FROM active_pointer WHERE id = 1"
        ).fetchone()
        assert (pointer["active_id"], pointer["revision"]) == (KEEPER, 3)

        # History rows were rewritten onto the keeper; revisions, timestamps
        # and row order are exactly as before.
        history = conn.execute(
            "SELECT seq, revision, previous_id, active_id, activated_at"
            " FROM active_history ORDER BY seq"
        ).fetchall()
        assert [tuple(r) for r in history] == [
            (1, 1, None, SOLO, "2026-01-04T00:00:00Z"),
            (2, 2, SOLO, KEEPER, "2026-01-05T00:00:00Z"),
            (3, 3, KEEPER, KEEPER, "2026-01-06T00:00:00Z"),
        ]

    # Starting up again must be an idempotent no-op.
    db.init_db()
    with db._connect() as conn:
        assert _ids(conn, "analyses", "id") == {KEEPER, SOLO}
        assert _hash_index_is_unique(conn)


def test_keeper_content_and_post_migration_saves(legacy_db) -> None:
    path, result = legacy_db
    db.init_db()

    from app.main import app

    with TestClient(app) as client:
        # The version list no longer contains duplicates.
        listing = client.get("/api/analyses").json()
        assert listing["total"] == 2
        assert sorted(a["id"] for a in listing["analyses"]) == [KEEPER, SOLO]

        # The keeper's stored result survived the migration verbatim.
        kept = client.get(f"/api/analyses/{KEEPER}").json()
        assert kept["ruleset_hash"] == result["ruleset_hash"]
        assert kept["rules"] == result["rules"]
        assert kept["findings"] == result["findings"]
        assert kept["name"] == "first-save"
        assert kept["created_at"] == _T1

        # Saving the same ruleset again deterministically reuses the keeper.
        for _ in range(2):
            r = client.post("/api/analyze", json={"rules": _RULESET})
            assert r.status_code == 200, r.text
            assert r.json()["id"] == KEEPER
            assert r.json()["persisted"] is True
        assert client.get("/api/analyses").json()["total"] == 2

        # The publication pointer survived the rewrite and keeps working:
        # re-publishing the keeper bumps the revision and appends history.
        active = client.get("/api/active").json()
        assert active == {"active_id": KEEPER, "revision": 3}
        r = client.post(
            "/api/active/activate",
            json={"analysis_id": KEEPER, "expected_revision": 3},
        )
        assert r.status_code == 200, r.text
        assert r.json()["active"]["revision"] == 4
        history = client.get("/api/active/history").json()
        assert history["total"] == 4
        assert [h["revision"] for h in history["history"]] == [4, 3, 2, 1]


def test_failed_migration_rolls_back_and_fails_startup(legacy_db) -> None:
    path, _result = legacy_db
    # Simulate a failure in the middle of the migration: any DELETE on
    # analyses aborts. init_db must raise (startup fails) and leave the
    # legacy database byte-for-byte in its pre-migration state.
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TRIGGER fail_analysis_delete BEFORE DELETE ON analyses"
            " BEGIN SELECT RAISE(ABORT, 'simulated migration failure'); END"
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(sqlite3.IntegrityError):
        db.init_db()

    with db._connect() as conn:
        # Duplicates are still there, the index is still non-unique, and the
        # pointer/history/rules/findings were not touched.
        assert not _hash_index_is_unique(conn)
        assert _ids(conn, "analyses", "id") == {KEEPER, DROPPED_LATER, DROPPED_TIE, SOLO}
        assert _ids(conn, "rules") == {KEEPER, DROPPED_LATER, DROPPED_TIE, SOLO}
        assert _ids(conn, "findings") == {KEEPER, DROPPED_LATER, DROPPED_TIE, SOLO}
        pointer = conn.execute(
            "SELECT active_id, revision FROM active_pointer WHERE id = 1"
        ).fetchone()
        assert (pointer["active_id"], pointer["revision"]) == (DROPPED_LATER, 3)
        history = conn.execute(
            "SELECT revision, previous_id, active_id FROM active_history ORDER BY seq"
        ).fetchall()
        assert [tuple(r) for r in history] == [
            (1, None, SOLO),
            (2, SOLO, DROPPED_LATER),
            (3, DROPPED_LATER, DROPPED_TIE),
        ]

    # Once the obstruction is removed the migration completes normally.
    with db._connect() as conn:
        conn.execute("DROP TRIGGER fail_analysis_delete")
    db.init_db()
    with db._connect() as conn:
        assert _hash_index_is_unique(conn)
        assert _ids(conn, "analyses", "id") == {KEEPER, SOLO}
