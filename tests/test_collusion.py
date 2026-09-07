import json
import time
from pathlib import Path

import pytest

from govern import engine
from govern.collusion import CollusionDetector
from govern.engine import Governor
from govern.policy import AggregateRule, Policy, PolicyError
from govern.simulate import simulate


def _base_policy_dict(aggregate_rule: dict) -> dict:
    return {
        "version": 1,
        "default_effect": "deny",
        "rules": [
            {"id": "allow-reads", "effect": "allow", "actions": ["*:Get*", "*:List*"]},
            {"id": "allow-writes", "effect": "allow", "actions": ["*:Put*", "*:Scale*"]},
        ],
        "aggregate_rules": [aggregate_rule],
    }


def _distinct_agents_rule(effect: str = "deny", max_agents: int = 3) -> dict:
    return {
        "id": "too-many-agents",
        "effect": effect,
        "description": "test rule",
        "actions": ["*:Get*"],
        "resources": ["shared-dataset"],
        "environments": ["production"],
        "window": "1h",
        "threshold": {"type": "distinct_agents", "max": max_agents},
    }


def _total_calls_rule(effect: str = "deny", max_calls: int = 3) -> dict:
    return {
        "id": "too-many-calls",
        "effect": effect,
        "description": "test rule",
        "actions": ["*:Scale*"],
        "resources": ["checkout"],
        "environments": ["production"],
        "window": "1h",
        "threshold": {"type": "total_calls", "max": max_calls},
    }


# -- live enforcement: distinct_agents --------------------------------------

def test_distinct_agents_threshold_trips_nth_call_in_live_enforcement(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_distinct_agents_rule(max_agents=3)))
    audit_log = tmp_path / "audit.jsonl"

    decisions = []
    for i in range(3):
        gov = Governor(
            agent_id=f"agent-{i}", environment="production", policy=policy,
            quiet=True, audit_log=audit_log,
        )
        decisions.append(gov.evaluate("s3:GetObject", "shared-dataset"))

    assert decisions[0].allowed is True
    assert decisions[1].allowed is True
    assert decisions[2].allowed is False
    assert decisions[2].rule_id == "too-many-agents"


# -- live enforcement: total_calls -------------------------------------------

def test_total_calls_threshold_trips_nth_call_in_live_enforcement(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_total_calls_rule(max_calls=3)))
    audit_log = tmp_path / "audit.jsonl"
    gov = Governor(
        agent_id="k8s-autoscaler", environment="production", policy=policy,
        quiet=True, audit_log=audit_log,
    )

    decisions = [gov.evaluate("k8s:ScaleDeployment", "checkout") for _ in range(3)]

    assert decisions[0].allowed is True
    assert decisions[1].allowed is True
    assert decisions[2].allowed is False
    assert decisions[2].rule_id == "too-many-calls"


# -- window expiry: tested directly against the standalone detector ---------

def test_window_expiry_excludes_old_events() -> None:
    rule = AggregateRule.from_dict(_distinct_agents_rule(max_agents=2), 0)
    detector = CollusionDetector([rule])
    now = time.time()

    r1 = detector.record({
        "action": "s3:GetObject", "resource": "shared-dataset", "environment": "production",
        "agent_id": "agent-old", "timestamp": now - 7200,  # 2h ago, outside the 1h window
    })
    r2 = detector.record({
        "action": "s3:GetObject", "resource": "shared-dataset", "environment": "production",
        "agent_id": "agent-new", "timestamp": now,
    })

    assert r1[0].triggered is False
    # only agent-new counts — agent-old's event aged out of the 1h window
    assert r2[0].count == 1
    assert r2[0].triggered is False


# -- deny override ------------------------------------------------------------

def test_deny_overrides_otherwise_allowed_decision_and_records_both(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_distinct_agents_rule(effect="deny", max_agents=2)))
    audit_log = tmp_path / "audit.jsonl"

    for i in range(2):
        gov = Governor(
            agent_id=f"agent-{i}", environment="production", policy=policy,
            quiet=True, audit_log=audit_log,
        )
        decision = gov.evaluate("s3:GetObject", "shared-dataset")

    # decision is now the 2nd (threshold-crossing) call
    assert decision.allowed is False
    assert decision.effect == "deny"
    assert decision.rule_id == "too-many-agents"
    assert decision.metadata["per_call_decision"]["effect"] == "allow"
    assert decision.metadata["per_call_decision"]["allowed"] is True
    assert decision.metadata["aggregate_rule"]["rule_id"] == "too-many-agents"

    lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
    last_entry = json.loads(lines[-1])
    assert last_entry["allowed"] is False
    assert last_entry["metadata"]["per_call_decision"]["allowed"] is True


# -- alert lets action through, writes distinguishable entry -----------------

def test_alert_lets_action_through_and_writes_collusion_entry(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_distinct_agents_rule(effect="alert", max_agents=2)))
    audit_log = tmp_path / "audit.jsonl"

    for i in range(2):
        gov = Governor(
            agent_id=f"agent-{i}", environment="production", policy=policy,
            quiet=True, audit_log=audit_log,
        )
        decision = gov.evaluate("s3:GetObject", "shared-dataset")

    # the underlying per-call decision (allow) stands even though the
    # aggregate rule tripped
    assert decision.allowed is True
    assert decision.effect == "allow"

    entries = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").strip().splitlines()]
    alert_entries = [e for e in entries if e.get("alert_type") == "collusion"]
    assert len(alert_entries) == 1
    assert alert_entries[0]["rule_id"] == "too-many-agents"
    assert set(alert_entries[0]["agent_ids"]) == {"agent-0", "agent-1"}
    # the normal decision entries are untouched (still show allow)
    decision_entries = [e for e in entries if not e.get("alert_type")]
    assert all(e["allowed"] for e in decision_entries)


# -- policy validate: schema rejection ---------------------------------------

def test_validate_rejects_duplicate_id_across_rules_and_aggregate_rules() -> None:
    raw = {
        "rules": [{"id": "shared-id", "effect": "allow"}],
        "aggregate_rules": [_distinct_agents_rule()],
    }
    raw["aggregate_rules"][0]["id"] = "shared-id"
    with pytest.raises(PolicyError, match="shared-id"):
        Policy.from_dict(raw)


def test_validate_rejects_invalid_threshold_type() -> None:
    rule = _distinct_agents_rule()
    rule["threshold"]["type"] = "distinct_snowflakes"
    with pytest.raises(PolicyError, match="too-many-agents") as excinfo:
        Policy.from_dict({"rules": [], "aggregate_rules": [rule]})
    assert "distinct_snowflakes" in str(excinfo.value)


def test_validate_rejects_invalid_effect_value() -> None:
    rule = _distinct_agents_rule()
    rule["effect"] = "block-with-extreme-prejudice"
    with pytest.raises(PolicyError, match="too-many-agents") as excinfo:
        Policy.from_dict({"rules": [], "aggregate_rules": [rule]})
    assert "block-with-extreme-prejudice" in str(excinfo.value)


# -- policy simulate populates collusion_alerts ------------------------------

def test_simulate_populates_collusion_alerts_for_new_aggregate_rule(tmp_path: Path) -> None:
    now = time.time()
    entries = [
        {
            "action": "s3:GetObject", "resource": "shared-dataset", "effect": "allow",
            "allowed": True, "reason": "read", "rule_id": "allow-reads", "severity": "info",
            "mode": "enforce", "agent_id": f"agent-{i}", "environment": "production",
            "session_id": "s1", "timestamp": now - (10 - i), "metadata": {},
        }
        for i in range(3)
    ]
    audit_log = tmp_path / "audit.jsonl"
    with audit_log.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")

    candidate = Policy.from_dict(_base_policy_dict(_distinct_agents_rule(max_agents=3)))
    result = simulate(candidate, audit_log)

    assert len(result.collusion_alerts) == 1
    assert result.collusion_alerts[0]["rule_id"] == "too-many-agents"
    assert result.collusion_alerts[0]["count"] == 3


def test_simulate_no_collusion_alerts_when_no_aggregate_rules(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("", encoding="utf-8")
    policy = Policy.bundled_default()
    result = simulate(policy, audit_log)
    assert result.collusion_alerts == []


# -- full regression: empty aggregate_rules changes nothing ------------------

def test_bundled_default_has_no_aggregate_rules() -> None:
    assert Policy.bundled_default().aggregate_rules == []


def test_empty_aggregate_rules_is_a_no_op_in_live_enforcement(tmp_path: Path) -> None:
    policy = Policy.bundled_default()
    audit_log = tmp_path / "audit.jsonl"
    gov = Governor(agent_id="agent-a", environment="production", policy=policy,
                    quiet=True, audit_log=audit_log)

    # same assertions as test_policy.py's existing coverage, just also
    # confirming the collusion wiring doesn't change any of it
    assert gov.evaluate("s3:ListBuckets", "prod-billing").allowed
    assert not gov.evaluate("s3:DeleteBucket", "prod-billing").allowed
    assert gov.collusion.rules == []
