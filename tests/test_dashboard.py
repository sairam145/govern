import json
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from govern.dashboard import create_app  # noqa: E402


def _write_log(path: Path, entries) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")


@pytest.fixture
def audit_log(tmp_path: Path) -> Path:
    now = time.time()
    entries = [
        {
            "action": "s3:ListBuckets", "resource": "*", "effect": "allow", "allowed": True,
            "reason": "read", "rule_id": "allow-reads", "severity": "info", "mode": "enforce",
            "agent_id": "agent-a", "environment": "production", "session_id": "s1",
            "timestamp": now - 30, "metadata": {},
        },
        {
            "action": "s3:DeleteBucket", "resource": "prod-billing", "effect": "deny", "allowed": False,
            "reason": "destructive", "rule_id": "deny-destructive-prod", "severity": "critical", "mode": "enforce",
            "agent_id": "agent-a", "environment": "production", "session_id": "s1",
            "timestamp": now - 20, "metadata": {},
        },
        {
            "action": "k8s:ScaleDeployment", "resource": "checkout", "effect": "require_approval", "allowed": False,
            "reason": "prod write", "rule_id": "approve-prod-writes", "severity": "medium", "mode": "monitor",
            "agent_id": "agent-b", "environment": "production", "session_id": "s2",
            "timestamp": now - 10, "metadata": {"would_have_blocked": True},
        },
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    return path


@pytest.fixture
def client(audit_log: Path) -> TestClient:
    return TestClient(create_app(audit_log=audit_log))


def test_events_returns_all_entries_newest_first(client: TestClient) -> None:
    resp = client.get("/api/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert [e["action"] for e in body["events"]] == [
        "k8s:ScaleDeployment", "s3:DeleteBucket", "s3:ListBuckets",
    ]


def test_events_filters_by_agent_id(client: TestClient) -> None:
    body = client.get("/api/events", params={"agent_id": "agent-a"}).json()
    assert body["total"] == 2
    assert all(e["agent_id"] == "agent-a" for e in body["events"])


def test_events_filters_by_effect(client: TestClient) -> None:
    body = client.get("/api/events", params={"effect": "deny"}).json()
    assert body["total"] == 1
    assert body["events"][0]["rule_id"] == "deny-destructive-prod"


def test_events_pagination(client: TestClient) -> None:
    body = client.get("/api/events", params={"limit": 1, "offset": 1}).json()
    assert body["total"] == 3
    assert len(body["events"]) == 1
    assert body["events"][0]["action"] == "s3:DeleteBucket"


def test_agents_summary(client: TestClient) -> None:
    agents = {a["agent_id"]: a for a in client.get("/api/agents").json()["agents"]}
    assert agents["agent-a"]["total_actions"] == 2
    assert agents["agent-a"]["allowed"] == 1
    assert agents["agent-a"]["blocked"] == 1
    # monitor mode still counts a would-have-blocked action as blocked
    assert agents["agent-b"]["total_actions"] == 1
    assert agents["agent-b"]["blocked"] == 1


def test_stats_buckets_allowed_and_blocked(client: TestClient) -> None:
    body = client.get("/api/stats", params={"since_hours": 1, "bucket_minutes": 60}).json()
    totals = {"allowed": 0, "blocked": 0}
    for bucket in body["buckets"]:
        totals["allowed"] += bucket["allowed"]
        totals["blocked"] += bucket["blocked"]
    assert totals == {"allowed": 1, "blocked": 2}


def test_agents_two_require_approval_refused_by_default_land_in_same_bucket(tmp_path: Path) -> None:
    """Regression test for a real corruption we hit: two Governor sessions
    for the same agent_id, both using the default (no) approval handler —
    which always refuses — must classify identically. The bug that
    prompted this wasn't in this classification logic (it's deterministic
    per session); it was tests/test_policy.py writing fixture Governors
    with *different* hardcoded approval callables to the real default
    audit log under a shared agent_id ("t"), making it look like the same
    agent got inconsistent treatment. See tests/conftest.py for the fix
    that isolates the audit log; this test locks in the behavior itself.
    """
    now = time.time()
    entries = [
        {
            "action": "s3:PutObject", "resource": "prod-billing", "effect": "require_approval",
            "allowed": False, "reason": "needs approval (human approval refused)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-c", "environment": "production", "session_id": "s3",
            "timestamp": now - 5, "metadata": {"approval": "refused"},
        },
        {
            "action": "k8s:ScaleDeployment", "resource": "checkout", "effect": "require_approval",
            "allowed": False, "reason": "needs approval (human approval refused)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-c", "environment": "production", "session_id": "s3",
            "timestamp": now - 3, "metadata": {"approval": "refused"},
        },
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    agent_c = {a["agent_id"]: a for a in TestClient(create_app(audit_log=path)).get("/api/agents").json()["agents"]}["agent-c"]

    assert agent_c["total_actions"] == 2
    assert agent_c["blocked"] == 2
    assert agent_c["allowed"] == 0
    assert agent_c["require_approval"] == 2
    assert agent_c["approvals_granted"] == 0
    assert agent_c["approvals_refused"] == 2


def test_agents_splits_granted_and_refused_approvals(tmp_path: Path) -> None:
    """Documents the intended behavior for point 3: when a real approval
    handler legitimately grants one call and refuses another for the same
    agent, allowed/blocked must reflect that real outcome (not be forced
    into one bucket) — while require_approval/approvals_* surface the
    approval gate itself as its own visible category, instead of the
    grant/refuse split being invisible inside allowed/blocked.
    """
    now = time.time()
    entries = [
        {
            "action": "s3:PutObject", "resource": "prod-billing", "effect": "require_approval",
            "allowed": True, "reason": "needs approval (human approval granted)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-d", "environment": "production", "session_id": "s4",
            "timestamp": now - 5, "metadata": {"approval": "granted"},
        },
        {
            "action": "s3:PutObject", "resource": "prod-billing", "effect": "require_approval",
            "allowed": False, "reason": "needs approval (human approval refused)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-d", "environment": "production", "session_id": "s5",
            "timestamp": now - 3, "metadata": {"approval": "refused"},
        },
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    agent_d = {a["agent_id"]: a for a in TestClient(create_app(audit_log=path)).get("/api/agents").json()["agents"]}["agent-d"]

    assert agent_d["allowed"] == 1
    assert agent_d["blocked"] == 1
    assert agent_d["require_approval"] == 2
    assert agent_d["approvals_granted"] == 1
    assert agent_d["approvals_refused"] == 1


def test_agents_require_approval_is_an_overlay_not_a_third_bucket(tmp_path: Path) -> None:
    """Locks in a deliberate design decision, not just a classification.

    require_approval always resolves synchronously in Governor.evaluate()
    before the event is ever written (see engine.py) — there is no
    deferred/async approval path in this codebase, so a require_approval
    event is never actually "pending" by the time it reaches the audit
    log. Splitting it into a third bucket mutually exclusive with
    allowed/blocked would relabel already-resolved outcomes as pending,
    which is less accurate, not more. allowed/blocked must always
    partition total_actions completely; require_approval/approvals_* are
    an overlay on top, not a third slice of the same pie.
    """
    now = time.time()
    entries = [
        {
            "action": "s3:PutObject", "resource": "prod-billing", "effect": "require_approval",
            "allowed": True, "reason": "needs approval (human approval granted)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-e", "environment": "production", "session_id": "s6",
            "timestamp": now - 5, "metadata": {"approval": "granted"},
        },
        {
            "action": "k8s:ScaleDeployment", "resource": "checkout", "effect": "require_approval",
            "allowed": False, "reason": "needs approval (human approval refused)",
            "rule_id": "approve-prod-writes", "severity": "medium", "mode": "enforce",
            "agent_id": "agent-e", "environment": "production", "session_id": "s6",
            "timestamp": now - 3, "metadata": {"approval": "refused"},
        },
        {
            "action": "s3:ListBuckets", "resource": "*", "effect": "allow", "allowed": True,
            "reason": "read", "rule_id": "allow-reads", "severity": "info", "mode": "enforce",
            "agent_id": "agent-e", "environment": "production", "session_id": "s6",
            "timestamp": now - 1, "metadata": {},
        },
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    agent_e = {a["agent_id"]: a for a in TestClient(create_app(audit_log=path)).get("/api/agents").json()["agents"]}["agent-e"]

    assert agent_e["total_actions"] == 3
    assert agent_e["allowed"] + agent_e["blocked"] == agent_e["total_actions"]
    assert agent_e["require_approval"] == 2  # counted again inside allowed/blocked, not separately


def test_stats_respects_since_hours_window(client: TestClient) -> None:
    body = client.get("/api/stats", params={"since_hours": 0.0001, "bucket_minutes": 60}).json()
    assert body["buckets"] == []
