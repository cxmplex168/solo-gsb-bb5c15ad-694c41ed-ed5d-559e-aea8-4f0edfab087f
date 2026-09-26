"""Regression tests for priorities outside SQLite's signed 64-bit INTEGER range.

A legal ``priority`` is any non-negative JSON integer (Python ints are
arbitrary precision), so it may exceed 2**63 - 1. SQLite INTEGER columns are
signed 64-bit and binding a larger value raises ``OverflowError``; the
persistence layer therefore stores ``priority`` as decimal TEXT (like
``covered``) and upgrades legacy INTEGER-priority databases at startup.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


# 2**63: one above the largest signed 64-bit value, the value in the bug
# report; plus a far larger value to prove storage is not REAL/lossy.
BIG = 9223372036854775808
HUGE = 10**40


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-prio-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _post(client: TestClient, rules: list[dict], **extra) -> dict:
    r = client.post("/api/analyze", json={"rules": rules, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def test_big_priority_is_saved_and_returned_as_exact_int(client: TestClient) -> None:
    data = _post(
        client,
        [
            {"rule_id": "big", "cidr": "10.0.0.0/8", "action": "permit", "priority": BIG},
            {"rule_id": "huge", "cidr": "10.1.0.0/16", "action": "deny", "priority": HUGE},
            {"rule_id": "plain", "cidr": "10.1.1.0/24", "action": "permit", "priority": 100},
        ],
    )
    assert data["persisted"] is True
    by_id = {r["rule_id"]: r["priority"] for r in data["rules"]}
    assert by_id == {"big": BIG, "huge": HUGE, "plain": 100}
    assert all(isinstance(v, int) for v in by_id.values())
    aid = data["id"]

    # GET /api/analyses/{id} returns the precise integer (result_json round trip).
    fetched = client.get(f"/api/analyses/{aid}").json()
    fetched_priority = {r["rule_id"]: r["priority"] for r in fetched["rules"]}
    assert fetched_priority == {"big": BIG, "huge": HUGE, "plain": 100}

    # GET /api/analyses/{id}/rules rebuilds rows from the decimal-TEXT column.
    rows = client.get(f"/api/analyses/{aid}/rules").json()["rules"]
    row_priority = {r["rule_id"]: r["priority"] for r in rows}
    assert row_priority == {"big": BIG, "huge": HUGE, "plain": 100}
    assert all(isinstance(r["priority"], int) for r in rows)


def test_big_priority_wire_format_is_an_integer_literal(client: TestClient) -> None:
    # No JSON string quotes and no REAL/scientific-notation rounding.
    aid = _post(
        client,
        [{"cidr": "10.0.0.0/8", "action": "permit", "priority": BIG}],
    )["id"]
    for url in (f"/api/analyses/{aid}", f"/api/analyses/{aid}/rules"):
        text = client.get(url).text
        assert '"priority":9223372036854775808' in text
        assert '"priority":"9223372036854775808"' not in text
        assert "9.223372036854776e+18" not in text


def test_big_priority_negative_is_rejected(client: TestClient) -> None:
    r = client.post(
        "/api/analyze",
        json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit", "priority": -1}]},
    )
    assert r.status_code == 422


def test_save_false_matches_saved_version(client: TestClient) -> None:
    rules = [
        {"rule_id": "lo", "cidr": "192.0.2.0/24", "action": "deny", "priority": BIG},
        {"rule_id": "hi", "cidr": "192.0.2.0/24", "action": "permit", "priority": 0},
        {"rule_id": "huge", "cidr": "2001:db8::/32", "action": "permit", "priority": HUGE},
    ]
    saved = _post(client, rules, name="kept")
    dry = _post(client, rules, name="draft", save=False)

    # Same fingerprint/version id and identical per-rule adjudication; nothing
    # is persisted by the dry run.
    assert dry["persisted"] is False
    assert dry["id"] == saved["id"]
    assert client.get("/api/analyses").json()["total"] == 1

    def _snapshot(d):
        return {
            r["rule_id"]: (r["priority"], r["role"], r["status"]) for r in d["rules"]
        }

    assert _snapshot(dry) == _snapshot(saved)


def test_duplicate_submission_reuses_one_version(client: TestClient) -> None:
    rules = [{"cidr": "10.0.0.0/8", "action": "permit", "priority": BIG}]
    first = _post(client, rules, name="first-name")
    second = _post(client, rules, name="ignored-name")
    assert second["id"] == first["id"]
    assert second["name"] == "first-name"
    assert second["persisted"] is True
    assert client.get("/api/analyses").json()["total"] == 1


def test_same_cidr_different_priority_adjudicated_by_priority(
    client: TestClient,
) -> None:
    # Smaller number wins even when the larger number is beyond 64 bits.
    data = _post(
        client,
        [
            {"rule_id": "huge", "cidr": "192.0.2.0/24", "action": "deny", "priority": HUGE},
            {"rule_id": "small", "cidr": "192.0.2.0/24", "action": "permit", "priority": 5},
        ],
    )
    role = {r["rule_id"]: r["role"] for r in data["rules"]}
    assert role == {"huge": "duplicate", "small": "winner"}

    # Reverse the action/priority pairing: a big-priority permit can win too.
    data = _post(
        client,
        [
            {"rule_id": "bigpermit", "cidr": "198.51.100.0/24", "action": "permit", "priority": BIG},
            {"rule_id": "plaindeny", "cidr": "198.51.100.0/24", "action": "deny", "priority": BIG + 1},
        ],
    )
    role = {r["rule_id"]: r["role"] for r in data["rules"]}
    assert role == {"bigpermit": "winner", "plaindeny": "duplicate"}


def test_same_cidr_same_big_priority_uses_submission_order(
    client: TestClient,
) -> None:
    data = _post(
        client,
        [
            {"rule_id": "x", "cidr": "192.0.2.0/24", "action": "permit", "priority": BIG},
            {"rule_id": "y", "cidr": "192.0.2.0/24", "action": "deny", "priority": BIG},
        ],
    )
    assert {r["rule_id"]: r["role"] for r in data["rules"]} == {
        "x": "winner",
        "y": "duplicate",
    }


def test_normal_priorities_are_unchanged(client: TestClient) -> None:
    data = _post(
        client,
        [
            {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
            {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200},
        ],
    )
    rows = client.get(f"/api/analyses/{data['id']}/rules").json()["rules"]
    assert {r["rule_id"]: r["priority"] for r in rows} == {"a": 100, "b": 200}
    # Filters on the rebuilt TEXT column keep working.
    filtered = client.get(
        f"/api/analyses/{data['id']}/rules", params={"action": "deny"}
    ).json()["rules"]
    assert [r["rule_id"] for r in filtered] == ["b"]


# ---------------------------------------------------------------------------
# Legacy database upgrade
# ---------------------------------------------------------------------------

# Exact table shape shipped before priority became TEXT (priority INTEGER).
_LEGACY_SCHEMA = """
CREATE TABLE analyses (
    id TEXT PRIMARY KEY, name TEXT, ruleset_hash TEXT NOT NULL,
    analyzer_version TEXT NOT NULL, created_at TEXT NOT NULL,
    rule_count INTEGER NOT NULL, result_json TEXT NOT NULL
);
CREATE TABLE rules (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_index INTEGER NOT NULL, rule_id TEXT NOT NULL, cidr TEXT NOT NULL,
    ip_version INTEGER NOT NULL, action TEXT NOT NULL, priority INTEGER NOT NULL,
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
CREATE UNIQUE INDEX idx_analyses_hash ON analyses(ruleset_hash);
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


def _seed_legacy_db(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_LEGACY_SCHEMA)
        conn.execute(
            "INSERT INTO analyses VALUES (?,?,?,?,?,?,?)",
            ("an_legacy000000000a", "old-name", "h_legacy", "1.0.0",
             "2026-01-01T00:00:00Z", 1, "{}"),
        )
        conn.execute(
            "INSERT INTO rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("an_legacy000000000a", 0, "r1", "10.0.0.0/8", 4, "permit", 100,
             "default", "active", "active", "16777216", 0),
        )
        conn.commit()
        # A legacy table really cannot hold an out-of-range priority.
        with pytest.raises(OverflowError):
            conn.execute(
                "INSERT INTO rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("an_legacy000000000a", 1, "r2", "10.0.0.0/9", 4, "deny", BIG,
                 "default", "duplicate", "shadowed", "0", 0),
            )
    finally:
        conn.close()


def test_legacy_integer_priority_db_is_upgraded_at_init() -> None:
    fd, tmp = tempfile.mkstemp(suffix=".db", prefix="ppa-test-legacy-")
    os.close(fd)
    os.remove(tmp)
    _seed_legacy_db(tmp)
    db.set_db_path(tmp)
    try:
        db.init_db()
        with db._connect() as conn:  # type: ignore[attr-defined]
            col_type = {
                row["name"]: (row["type"] or "").upper()
                for row in conn.execute("PRAGMA table_info(rules)")
            }["priority"]
            assert col_type == "TEXT"
            stored = conn.execute(
                "SELECT priority, typeof(priority) FROM rules"
            ).fetchone()
            assert tuple(stored) == ("100", "text")
            # Analysis FK relationship survived the table rebuild.
            fk_ok = conn.execute(
                "SELECT COUNT(*) AS c FROM rules r JOIN analyses a ON r.analysis_id = a.id"
            ).fetchone()["c"]
            assert fk_ok == 1

        # Starting up again must be an idempotent no-op.
        db.init_db()

        # Existing data reads back as int, and new big priorities now save.
        from app.main import app

        with TestClient(app) as client:
            legacy_rules = client.get(
                "/api/analyses/an_legacy000000000a/rules"
            ).json()["rules"]
            assert legacy_rules[0]["priority"] == 100
            assert isinstance(legacy_rules[0]["priority"], int)

            saved = _post(
                client,
                [{"cidr": "10.0.0.0/8", "action": "permit", "priority": BIG}],
            )
            assert saved["persisted"] is True
            rows = client.get(
                f"/api/analyses/{saved['id']}/rules"
            ).json()["rules"]
            assert rows[0]["priority"] == BIG
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(tmp + suffix)
            except OSError:
                pass
