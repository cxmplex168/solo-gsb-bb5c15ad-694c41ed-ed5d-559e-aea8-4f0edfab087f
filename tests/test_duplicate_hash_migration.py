"""Regression tests for the legacy duplicate-``ruleset_hash`` upgrade.

Databases written before saves were serialized by the unique
``idx_analyses_hash`` index can hold several analysis versions for one
``ruleset_hash`` (the old racy save let concurrent inserts through). The
previous startup migration rolled the failing unique-index creation back
but then continued anyway, leaving duplicates in the version list and
making the save path's reuse lookup pick an arbitrary version. ``init_db``
now collapses the duplicates onto the earliest-saved version inside one
transaction — repointing the publication pointer and history, deleting the
redundant versions' rules/findings/analyses rows — creates the unique
index, and any failure rolls everything back and aborts startup.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


# Current table shapes, except that idx_analyses_hash is the legacy
# NON-UNIQUE index shipped before saves were deduplicated atomically.
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

# Ids are chosen so that id order and created_at order disagree, proving the
# keep decision is driven by (created_at, id): the earliest save wins even
# when a redundant duplicate has a smaller id.
KEEP_A = "an_00000000000000c3"  # h_dup, created 2026-01-01 -> kept
DUP_A1 = "an_00000000000000a1"  # h_dup, created 2026-01-02 -> redundant
DUP_A2 = "an_00000000000000b2"  # h_dup, created 2026-01-02 -> redundant
KEEP_B = "an_00000000000000f6"  # h_dup2, created 2026-01-03 -> kept
DUP_B = "an_00000000000000a7"  # h_dup2, created 2026-01-04 -> redundant
SOLO = "an_00000000000000e5"  # h_solo, the only version of its hash

_ANALYSES = [
    # (id, name, ruleset_hash, created_at)
    (KEEP_A, "dup-earliest", "h_dup", "2026-01-01T00:00:00Z"),
    (DUP_A1, "dup-later-small-id", "h_dup", "2026-01-02T00:00:00Z"),
    (DUP_A2, "dup-later", "h_dup", "2026-01-02T00:00:00Z"),
    (KEEP_B, "dup2-earliest", "h_dup2", "2026-01-03T00:00:00Z"),
    (DUP_B, "dup2-later-small-id", "h_dup2", "2026-01-04T00:00:00Z"),
    (SOLO, "solo", "h_solo", "2026-01-05T00:00:00Z"),
]

_HISTORY = [
    # (revision, previous_id, active_id, activated_at)
    (1, None, DUP_A2, "2026-02-01T00:00:00Z"),
    (2, DUP_A2, DUP_A1, "2026-02-02T00:00:00Z"),
    (3, DUP_A1, DUP_B, "2026-02-03T00:00:00Z"),
]


def _seed_legacy_db(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_LEGACY_SCHEMA)
        for analysis_id, name, ruleset_hash, created_at in _ANALYSES:
            conn.execute(
                "INSERT INTO analyses VALUES (?,?,?,?,?,?,?)",
                (
                    analysis_id,
                    name,
                    ruleset_hash,
                    "1.0.0",
                    created_at,
                    1,
                    f'{{"ruleset_hash": "{ruleset_hash}", "marker": "{analysis_id}"}}',
                ),
            )
            conn.execute(
                "INSERT INTO rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    analysis_id,
                    0,
                    "r1",
                    "10.0.0.0/8",
                    4,
                    "permit",
                    "100",
                    "default",
                    "winner",
                    "active",
                    "16777216",
                    0,
                ),
            )
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
                (
                    analysis_id,
                    0,
                    "cover",
                    "info",
                    "r1",
                    None,
                    0,
                    f'{{"marker": "{analysis_id}"}}',
                ),
            )
        conn.executemany(
            "INSERT INTO active_history (revision, previous_id, active_id, activated_at)"
            " VALUES (?,?,?,?)",
            _HISTORY,
        )
        # The pointer sits on a redundant duplicate at the latest revision.
        conn.execute(
            "UPDATE active_pointer SET active_id = ?, revision = 3 WHERE id = 1",
            (DUP_A1,),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def legacy_db_path():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-hashdup-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    _seed_legacy_db(path)
    db.set_db_path(path)
    yield path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _fetch_all(path: str, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def test_duplicate_hashes_are_collapsed_onto_earliest_save(legacy_db_path: str) -> None:
    db.init_db()

    # Exactly one version per ruleset_hash survives: the earliest save by
    # (created_at, id), with its own metadata untouched.
    analyses = dict(
        _fetch_all(
            legacy_db_path,
            "SELECT id, name || '|' || ruleset_hash || '|' || created_at FROM analyses",
        )
    )
    assert analyses == {
        KEEP_A: "dup-earliest|h_dup|2026-01-01T00:00:00Z",
        KEEP_B: "dup2-earliest|h_dup2|2026-01-03T00:00:00Z",
        SOLO: "solo|h_solo|2026-01-05T00:00:00Z",
    }

    # The redundant versions' rules/findings are gone; the kept versions'
    # rows are intact.
    rule_owners = {
        row[0] for row in _fetch_all(legacy_db_path, "SELECT DISTINCT analysis_id FROM rules")
    }
    finding_owners = {
        row[0]
        for row in _fetch_all(legacy_db_path, "SELECT DISTINCT analysis_id FROM findings")
    }
    assert rule_owners == finding_owners == {KEEP_A, KEEP_B, SOLO}

    # The pointer is repointed at the kept version; its revision is unchanged.
    assert _fetch_all(legacy_db_path, "SELECT active_id, revision FROM active_pointer") == [
        (KEEP_A, 3)
    ]

    # History references are repointed while revision, timestamp and row
    # order are preserved exactly.
    assert _fetch_all(
        legacy_db_path,
        "SELECT seq, revision, previous_id, active_id, activated_at"
        " FROM active_history ORDER BY seq",
    ) == [
        (1, 1, None, KEEP_A, "2026-02-01T00:00:00Z"),
        (2, 2, KEEP_A, KEEP_A, "2026-02-02T00:00:00Z"),
        (3, 3, KEEP_A, KEEP_B, "2026-02-03T00:00:00Z"),
    ]

    # The unique index now backs the dedup invariant.
    assert _fetch_all(
        legacy_db_path,
        "SELECT \"unique\" FROM pragma_index_list('analyses')"
        " WHERE name = 'idx_analyses_hash'",
    ) == [(1,)]

    # Re-running the upgrade is an idempotent no-op.
    db.init_db()
    assert _fetch_all(legacy_db_path, "SELECT COUNT(*) FROM analyses") == [(3,)]

    # The migrated database serves the API: no duplicate versions in the
    # list, the kept version reads back verbatim, redundant versions are 404,
    # and the pointer/history endpoints show the repointed state.
    from app.main import app

    with TestClient(app) as client:
        listing = client.get("/api/analyses").json()
        assert listing["total"] == 3
        assert [a["id"] for a in listing["analyses"]] == [SOLO, KEEP_B, KEEP_A]

        kept = client.get(f"/api/analyses/{KEEP_A}").json()
        assert kept["marker"] == KEEP_A
        assert kept["name"] == "dup-earliest"
        assert kept["created_at"] == "2026-01-01T00:00:00Z"

        assert client.get(f"/api/analyses/{DUP_A1}").status_code == 404
        assert client.get(f"/api/analyses/{DUP_B}").status_code == 404

        assert client.get("/api/active").json() == {"active_id": KEEP_A, "revision": 3}
        history = client.get("/api/active/history").json()
        assert history["total"] == 3
        assert [
            (h["revision"], h["previous_id"], h["active_id"]) for h in history["history"]
        ] == [
            (3, KEEP_A, KEEP_B),
            (2, KEEP_A, KEEP_A),
            (1, None, KEEP_A),
        ]

        # Saving on the migrated database is deterministic again: a repeated
        # submission reuses exactly one version.
        rules = [{"cidr": "192.0.2.0/24", "action": "deny"}]
        first = client.post("/api/analyze", json={"rules": rules}).json()
        second = client.post("/api/analyze", json={"rules": rules}).json()
        assert first["id"] == second["id"]
        assert client.get("/api/analyses").json()["total"] == 4


def test_legacy_db_without_duplicates_just_gets_the_unique_index(
    legacy_db_path: str,
) -> None:
    # Remove the duplicate groups, keeping one version per hash.
    conn = sqlite3.connect(legacy_db_path)
    try:
        conn.execute(
            "DELETE FROM analyses WHERE id IN (?, ?, ?)", (DUP_A1, DUP_A2, DUP_B)
        )
        conn.execute("DELETE FROM rules WHERE analysis_id NOT IN (SELECT id FROM analyses)")
        conn.execute(
            "DELETE FROM findings WHERE analysis_id NOT IN (SELECT id FROM analyses)"
        )
        conn.execute("DELETE FROM active_history")
        conn.execute("UPDATE active_pointer SET active_id = ?, revision = 0", (KEEP_A,))
        conn.commit()
    finally:
        conn.close()

    db.init_db()

    assert _fetch_all(
        legacy_db_path,
        "SELECT \"unique\" FROM pragma_index_list('analyses')"
        " WHERE name = 'idx_analyses_hash'",
    ) == [(1,)]
    # Every version is untouched.
    assert {
        row[0]
        for row in _fetch_all(legacy_db_path, "SELECT id FROM analyses")
    } == {KEEP_A, KEEP_B, SOLO}
    assert _fetch_all(legacy_db_path, "SELECT active_id, revision FROM active_pointer") == [
        (KEEP_A, 0)
    ]


def test_failed_migration_rolls_back_everything_and_raises(legacy_db_path: str) -> None:
    # A trigger that aborts the analyses delete simulates a mid-migration
    # failure; nothing may survive it, and startup must report the error.
    conn = sqlite3.connect(legacy_db_path)
    try:
        conn.execute(
            "CREATE TRIGGER abort_analysis_delete BEFORE DELETE ON analyses "
            "BEGIN SELECT RAISE(ABORT, 'simulated migration failure'); END"
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(sqlite3.IntegrityError):
        db.init_db()

    # The whole transaction was rolled back: all six versions, their rows,
    # the pointer, the history and the legacy non-unique index are exactly
    # as before the failed upgrade.
    assert _fetch_all(legacy_db_path, "SELECT COUNT(*) FROM analyses") == [(6,)]
    assert _fetch_all(legacy_db_path, "SELECT COUNT(*) FROM rules") == [(6,)]
    assert _fetch_all(legacy_db_path, "SELECT COUNT(*) FROM findings") == [(6,)]
    assert _fetch_all(legacy_db_path, "SELECT active_id, revision FROM active_pointer") == [
        (DUP_A1, 3)
    ]
    assert _fetch_all(
        legacy_db_path,
        "SELECT revision, previous_id, active_id, activated_at"
        " FROM active_history ORDER BY seq",
    ) == _HISTORY
    assert _fetch_all(
        legacy_db_path,
        "SELECT \"unique\" FROM pragma_index_list('analyses')"
        " WHERE name = 'idx_analyses_hash'",
    ) == [(0,)]

    # Once the cause is fixed, the same database upgrades cleanly — the
    # failed attempt left no partial state behind.
    conn = sqlite3.connect(legacy_db_path)
    try:
        conn.execute("DROP TRIGGER abort_analysis_delete")
        conn.commit()
    finally:
        conn.close()
    db.init_db()
    assert _fetch_all(legacy_db_path, "SELECT COUNT(*) FROM analyses") == [(3,)]
    assert _fetch_all(
        legacy_db_path,
        "SELECT \"unique\" FROM pragma_index_list('analyses')"
        " WHERE name = 'idx_analyses_hash'",
    ) == [(1,)]
