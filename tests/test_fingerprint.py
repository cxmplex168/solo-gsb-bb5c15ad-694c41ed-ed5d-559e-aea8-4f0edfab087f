"""Ruleset fingerprint (ruleset_hash) canonicalization tests.

The version fingerprint must ignore submission reorderings that cannot change
the verdict, while preserving every ordering that does:

* different CIDRs adjudicate by longest-prefix match — their relative order is
  irrelevant, so swapping them must not change the fingerprint;
* same-CIDR rules with different priorities are adjudicated by priority alone —
  their relative order is irrelevant too;
* same-CIDR rules with the *same* priority are adjudicated by input order —
  their relative order decides the winning ``rule_id`` and must keep
  distinguishing fingerprints;
* rules without an explicit ``rule_id`` are fingerprinted by their generated
  positional ids (``r1``, ``r2``, ...), so reordering them still differs.
"""

from __future__ import annotations

import os
import random
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db
from app.analyzer import analyze_rules


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-fp-")
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


# Two rules whose relative order cannot influence the verdict: longest-prefix
# match adjudicates across different CIDRs regardless of submission order.
ORDER_INDEPENDENT = [
    {"rule_id": "p8", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "hq"},
    {"rule_id": "d16", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "p24", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
    {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
]


def _shuffled(rules: list[dict], seed: int) -> list[dict]:
    clone = [dict(r) for r in rules]
    random.Random(seed).shuffle(clone)
    return clone


# ---------------------------------------------------------------------------
# Analyzer-level fingerprint semantics
# ---------------------------------------------------------------------------
def test_hash_ignores_verdict_neutral_reordering() -> None:
    first = analyze_rules([dict(r) for r in ORDER_INDEPENDENT])
    for seed in range(5):
        shuffled = analyze_rules(_shuffled(ORDER_INDEPENDENT, seed))
        assert shuffled["ruleset_hash"] == first["ruleset_hash"]


def test_hash_ignores_same_cidr_priority_swap() -> None:
    # Same CIDR, different priorities: priority alone picks the winner, so the
    # submission order of these two rules is verdict-neutral.
    a = analyze_rules([
        {"rule_id": "lo", "cidr": "192.0.2.0/24", "action": "deny", "priority": 200},
        {"rule_id": "hi", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
    ])
    b = analyze_rules([
        {"rule_id": "hi", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
        {"rule_id": "lo", "cidr": "192.0.2.0/24", "action": "deny", "priority": 200},
    ])
    assert a["ruleset_hash"] == b["ruleset_hash"]


def test_hash_preserves_same_cidr_same_priority_relative_order() -> None:
    # Same CIDR *and* same priority: input order is the tie-break that decides
    # the winning rule_id, so swapping the rules must change the fingerprint.
    a = analyze_rules([
        {"rule_id": "x", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
        {"rule_id": "y", "cidr": "192.0.2.0/24", "action": "deny", "priority": 100},
    ])
    b = analyze_rules([
        {"rule_id": "y", "cidr": "192.0.2.0/24", "action": "deny", "priority": 100},
        {"rule_id": "x", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
    ])
    assert a["ruleset_hash"] != b["ruleset_hash"]
    # ... and the verdict really does change: the first rule wins the tie.
    winner_a = next(r for r in a["rules"] if r["role"] == "winner")
    winner_b = next(r for r in b["rules"] if r["role"] == "winner")
    assert winner_a["rule_id"] == "x"
    assert winner_b["rule_id"] == "y"


def test_hash_distinguishes_unlabeled_rules_by_generated_ids() -> None:
    # Without explicit rule_id the generated ids are positional (r1, r2, ...):
    # reordering reshuffles which rule wears which id, so the fingerprints
    # still differ.
    a = analyze_rules([
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "deny"},
    ])
    b = analyze_rules([
        {"cidr": "10.1.0.0/16", "action": "deny"},
        {"cidr": "10.0.0.0/8", "action": "permit"},
    ])
    assert a["ruleset_hash"] != b["ruleset_hash"]
    # Identical input is of course still stable.
    again = analyze_rules([
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "deny"},
    ])
    assert again["ruleset_hash"] == a["ruleset_hash"]


# ---------------------------------------------------------------------------
# API level: dedup across verdict-neutral reorderings
# ---------------------------------------------------------------------------
def test_reordered_explicit_id_submission_dedups_to_one_version(client: TestClient) -> None:
    first = client.post(
        "/api/analyze", json={"name": "first", "rules": ORDER_INDEPENDENT}
    ).json()
    for seed in range(3):
        dup = client.post(
            "/api/analyze",
            json={"name": f"dup-{seed}", "rules": _shuffled(ORDER_INDEPENDENT, seed)},
        ).json()
        # Same fingerprint, same version id, first version's metadata reused.
        assert dup["ruleset_hash"] == first["ruleset_hash"]
        assert dup["id"] == first["id"]
        assert dup["name"] == "first"
        assert dup["created_at"] == first["created_at"]
        assert dup["persisted"] is True
        # The duplicate response is the stored first version verbatim.
        assert dup["rules"] == first["rules"]

    assert client.get("/api/analyses").json()["total"] == 1

    fetched = client.get(f"/api/analyses/{first['id']}").json()
    assert fetched["ruleset_hash"] == first["ruleset_hash"]
    assert fetched["rules"] == first["rules"]


def test_save_false_and_save_compute_the_same_fingerprint(client: TestClient) -> None:
    saved = client.post("/api/analyze", json={"rules": ORDER_INDEPENDENT}).json()
    dry = client.post(
        "/api/analyze",
        json={"save": False, "rules": _shuffled(ORDER_INDEPENDENT, 11)},
    ).json()
    assert dry["persisted"] is False
    assert dry["ruleset_hash"] == saved["ruleset_hash"]
    assert dry["id"] == saved["id"]
    # The dry run did not create another version.
    assert client.get("/api/analyses").json()["total"] == 1


def test_same_cidr_same_priority_swap_stays_two_versions(client: TestClient) -> None:
    rules = [
        {"rule_id": "x", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
        {"rule_id": "y", "cidr": "192.0.2.0/24", "action": "deny", "priority": 100},
    ]
    first = client.post("/api/analyze", json={"rules": rules}).json()
    swapped = client.post("/api/analyze", json={"rules": list(reversed(rules))}).json()
    assert swapped["ruleset_hash"] != first["ruleset_hash"]
    assert swapped["id"] != first["id"]
    assert client.get("/api/analyses").json()["total"] == 2


def test_unlabeled_reorder_stays_two_versions(client: TestClient) -> None:
    rules = [
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "deny"},
    ]
    first = client.post("/api/analyze", json={"rules": rules}).json()
    swapped = client.post("/api/analyze", json={"rules": list(reversed(rules))}).json()
    assert swapped["ruleset_hash"] != first["ruleset_hash"]
    assert client.get("/api/analyses").json()["total"] == 2
