"""Regression tests: scoped (zoned) IPv6 CIDRs are rejected at every entry point.

``ipaddress`` accepts literals like ``fe80::%eth0/128``, but the scope id
makes the network overlap its unscoped twin without containing it: the pair
``fe80::/128`` + ``fe80::%eth0/128`` was analysed as two distinct winning
networks over the *same* address while the decision map reported a single
action — silent coverage distortion.  Network policy has no notion of
interface scopes, so rule submission, change simulation, merge precheck, the
decision-map query, the quarantine target and change-guard authorizations
all reject ``%``-carrying IPv6 CIDRs in each entry point's own error format,
and a rejected batch is never partially saved.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-scoped-")
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


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _saved_total(client: TestClient) -> int:
    return client.get("/api/analyses").json()["total"]


# ---------------------------------------------------------------------------
# Rule submission (POST /api/analyze)
# ---------------------------------------------------------------------------
def test_analyze_rejects_the_reported_scoped_pair(client: TestClient) -> None:
    # The exact distortion scenario: an unscoped /128 and its scoped twin must
    # no longer be accepted as two winning networks over one address.
    r = client.post(
        "/api/analyze",
        json={
            "rules": [
                {"rule_id": "a", "cidr": "fe80::/128", "action": "permit"},
                {"rule_id": "b", "cidr": "fe80::%eth0/128", "action": "deny"},
            ]
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_ruleset"
    assert "invalid CIDR" in body["detail"]
    assert "fe80::%eth0/128" in body["detail"]
    # The whole batch is rejected: nothing was saved, not even the valid rule.
    assert _saved_total(client) == 0


def test_analyze_rejects_scoped_ipv6_variants(client: TestClient) -> None:
    for bad in ("fe80::%eth0/128", "fe80::%1/128", "2001:db8::%vlan10/32", "FE80::%ETH0/128"):
        r = client.post("/api/analyze", json={"rules": [{"cidr": bad, "action": "permit"}]})
        assert r.status_code == 400, (bad, r.status_code)
        assert r.json()["error"] == "invalid_ruleset"
        assert "invalid CIDR" in r.json()["detail"]
    assert _saved_total(client) == 0


def test_analyze_mixed_batch_with_one_scoped_rule_saves_nothing(client: TestClient) -> None:
    r = client.post(
        "/api/analyze",
        json={
            "rules": [
                {"cidr": "10.0.0.0/8", "action": "permit"},
                {"cidr": "2001:db8::/32", "action": "deny"},
                {"cidr": "fe80::%eth0/64", "action": "deny"},
            ]
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    # All-or-nothing: the valid IPv4/IPv6 rules of the batch are not persisted.
    assert _saved_total(client) == 0


def test_unscoped_ipv6_still_accepted_and_mapped_consistently(client: TestClient) -> None:
    # The unscoped half of the reported pair keeps working, and the decision
    # map agrees with the analysis on the winning action.
    aid = _save(client, [{"rule_id": "a", "cidr": "fe80::/128", "action": "permit"}])
    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "fe80::/128"})
    assert r.status_code == 200
    blocks = r.json()["blocks"]
    assert len(blocks) == 1
    assert blocks[0]["action"] == "permit"
    assert blocks[0]["winner_rule_id"] == "a"


def test_same_cidr_priority_adjudication_still_works(client: TestClient) -> None:
    # Same-CIDR ties are still decided by priority (smaller number wins), the
    # loser stays a shadowed duplicate, and the map reports the winner.
    aid = _save(
        client,
        [
            {"rule_id": "hi", "cidr": "fe80::/64", "action": "permit", "priority": 10},
            {"rule_id": "lo", "cidr": "fe80::/64", "action": "deny", "priority": 20},
        ],
    )
    rules = {r["rule_id"]: r for r in client.get(f"/api/analyses/{aid}").json()["rules"]}
    assert rules["hi"]["role"] == "winner" and rules["hi"]["status"] == "active"
    assert rules["lo"]["role"] == "duplicate" and rules["lo"]["status"] == "shadowed"
    blocks = client.get(
        f"/api/analyses/{aid}/decision-map", params={"cidr": "fe80::/64"}
    ).json()["blocks"]
    assert len(blocks) == 1
    assert blocks[0]["action"] == "permit"
    assert blocks[0]["winner_rule_id"] == "hi"
    # Plain IPv4 adjudication is untouched as well.
    aid4 = _save(
        client,
        [
            {"cidr": "10.0.0.0/8", "action": "permit"},
            {"cidr": "10.1.0.0/16", "action": "deny"},
        ],
    )
    rules4 = client.get(f"/api/analyses/{aid4}").json()["rules"]
    assert {r["status"] for r in rules4} == {"partial", "active"}


# ---------------------------------------------------------------------------
# Change simulation (POST /api/analyses/{id}/simulate)
# ---------------------------------------------------------------------------
def test_simulate_rejects_scoped_add_and_replace(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "fe80::/64", "action": "permit"}])

    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "s1", "cidr": "fe80::%eth0/128", "action": "deny"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    assert "invalid CIDR" in r.json()["detail"]

    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{"rule_id": "a", "cidr": "fe80::%eth0/64", "action": "deny"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"

    # The base version is untouched and no new version was created.
    assert _saved_total(client) == 1
    assert len(client.get(f"/api/analyses/{aid}").json()["rules"]) == 1


# ---------------------------------------------------------------------------
# Merge precheck (POST /api/analyses/{id}/merge-precheck)
# ---------------------------------------------------------------------------
def test_merge_precheck_rejects_scoped_cidr(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "fe80::/64", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/merge-precheck",
        json={
            "a": {"add": [{"rule_id": "x", "cidr": "fe80::1/128", "action": "deny"}]},
            "b": {"add": [{"rule_id": "y", "cidr": "fe80::%eth0/128", "action": "deny"}]},
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    assert _saved_total(client) == 1


# ---------------------------------------------------------------------------
# Decision map (GET /api/analyses/{id}/decision-map)
# ---------------------------------------------------------------------------
def test_decision_map_rejects_scoped_query(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "fe80::/64", "action": "permit"}])
    for bad in ("fe80::%eth0/128", "fe80::%1/64"):
        r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": bad})
        assert r.status_code == 400, (bad, r.status_code)
        assert r.json()["error"] == "invalid_cidr"
        assert "invalid CIDR" in r.json()["detail"]

    # A scoped query is rejected even when the version does not exist:
    # query validation runs before the version lookup.
    r = client.get(
        "/api/analyses/an_0000000000000000/decision-map", params={"cidr": "fe80::%eth0/128"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_cidr"


# ---------------------------------------------------------------------------
# Quarantine plan (POST /api/analyses/{id}/quarantine-plan)
# ---------------------------------------------------------------------------
def test_quarantine_plan_rejects_scoped_target(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "fe80::/64", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "fe80::%eth0/64", "rule_id_prefix": "q"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_cidr"
    assert "invalid CIDR" in r.json()["detail"]

    # Rejected before the version lookup, and nothing is persisted.
    r = client.post(
        "/api/analyses/an_0000000000000000/quarantine-plan",
        json={"cidr": "fe80::%eth0/64", "rule_id_prefix": "q"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_cidr"
    assert _saved_total(client) == 1


# ---------------------------------------------------------------------------
# Change guard (POST /api/analyses/{base}/change-guard/{target})
# ---------------------------------------------------------------------------
def test_change_guard_rejects_scoped_authorization(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "fe80::/64", "action": "permit"}], name="v1")
    target_id = _save(client, [{"cidr": "fe80::/64", "action": "deny"}], name="v2")

    r = client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}",
        json={
            "authorizations": [
                {"cidr": "fe80::%eth0/64", "from_action": "permit", "to_action": "deny"},
                {"cidr": "10.0.0.5/24", "from_action": "permit", "to_action": "deny"},
            ]
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_change_guard"
    # Every offending authorization is reported at once, in order.
    assert len(body["issues"]) == 2
    assert "authorization #1" in body["issues"][0]
    assert "fe80::%eth0/64" in body["issues"][0]
    assert "authorization #2" in body["issues"][1]

    # The same transition with an unscoped grant still passes.
    ok = client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}",
        json={
            "authorizations": [
                {"cidr": "fe80::/64", "from_action": "permit", "to_action": "deny"}
            ]
        },
    )
    assert ok.status_code == 200
    assert ok.json()["passed"] is True
