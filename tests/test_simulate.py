import json
import time
from pathlib import Path

import pytest

from govern import cli
from govern.policy import Policy
from govern.simulate import simulate


def _write_log(path: Path, entries) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")


def _entry(**overrides):
    base = {
        "action": "s3:ListBuckets", "resource": "*", "effect": "allow", "allowed": True,
        "reason": "read", "rule_id": "allow-reads", "severity": "info", "mode": "enforce",
        "agent_id": "agent-a", "environment": "production", "session_id": "s1",
        "timestamp": time.time(), "metadata": {},
    }
    base.update(overrides)
    return base


@pytest.fixture
def history(tmp_path: Path) -> Path:
    now = time.time()
    entries = [
        _entry(action="s3:ListBuckets", resource="*", effect="allow", allowed=True,
               rule_id="allow-reads", severity="info", timestamp=now - 3600),
        _entry(action="s3:DeleteBucket", resource="prod-billing", effect="deny", allowed=False,
               rule_id="deny-destructive-prod", severity="critical", timestamp=now - 1800),
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    return path


def _base_policy_dict():
    return {
        "version": 1,
        "default_effect": "deny",
        "rules": [
            {"id": "allow-reads", "effect": "allow", "severity": "info", "actions": ["*:List*"]},
            {"id": "deny-destructive-prod", "effect": "deny", "severity": "critical",
             "actions": ["*:Delete*"], "environments": ["production"]},
        ],
    }


def test_new_deny_rule_flags_previously_allowed_events(tmp_path: Path, history: Path) -> None:
    """A candidate policy that adds a new deny rule must show the
    previously-allowed matching event as newly blocked, while the
    already-blocked event stays unaffected."""
    candidate = _base_policy_dict()
    candidate["rules"].append({
        "id": "deny-list-everywhere", "effect": "deny", "severity": "high",
        "actions": ["*:ListBuckets"],
    })
    policy = Policy.from_dict(candidate, source="candidate")

    result = simulate(policy, history)

    assert result.total_events == 2
    assert len(result.changed) == 1
    changed = result.changed[0]
    assert changed.action == "s3:ListBuckets"
    assert changed.old_effect == "allow"
    assert changed.new_effect == "deny"
    assert changed.new_rule_id == "deny-list-everywhere"
    assert changed.is_new_denial is True
    assert result.new_denials == [changed]


def test_removed_rule_flags_previously_blocked_events_as_would_allow(
    tmp_path: Path, history: Path
) -> None:
    """Removing the rule that used to deny an action must show that
    historical event as would-now-be-allowed."""
    candidate = _base_policy_dict()
    candidate["rules"] = [r for r in candidate["rules"] if r["id"] != "deny-destructive-prod"]
    policy = Policy.from_dict(candidate, source="candidate")

    # Removing the rule alone doesn't flip anything yet: with no rule
    # matching, evaluation falls through to default_effect, which is
    # still "deny" — so nothing should be reported as changed.
    result = simulate(policy, history)
    assert len(result.changed) == 0

    # Only when default_effect also becomes "allow" does the historical
    # deny actually flip to would-now-be-allowed.
    candidate["default_effect"] = "allow"
    policy2 = Policy.from_dict(candidate, source="candidate-2")
    result2 = simulate(policy2, history)

    assert len(result2.changed) == 1
    changed2 = result2.changed[0]
    assert changed2.action == "s3:DeleteBucket"
    assert changed2.old_effect == "deny"
    assert changed2.new_effect == "allow"
    assert changed2.is_new_denial is False


def test_since_filters_events_outside_the_window(tmp_path: Path) -> None:
    now = time.time()
    entries = [
        _entry(action="s3:ListBuckets", timestamp=now - 10 * 3600),  # inside a 24h window
        _entry(action="s3:PutObject", effect="deny", allowed=False,
               timestamp=now - 48 * 3600),  # outside a 24h window
    ]
    path = tmp_path / "audit.jsonl"
    _write_log(path, entries)
    policy = Policy.from_dict(_base_policy_dict(), source="candidate")

    result_all = simulate(policy, path)
    assert result_all.total_events == 2

    result_windowed = simulate(policy, path, since_hours=24)
    assert result_windowed.total_events == 1


def test_fail_on_new_blocks_exit_code(tmp_path: Path, history: Path) -> None:
    candidate_with_new_deny = _base_policy_dict()
    candidate_with_new_deny["rules"].append({
        "id": "deny-list-everywhere", "effect": "deny", "severity": "high",
        "actions": ["*:ListBuckets"],
    })
    candidate_path = tmp_path / "candidate.yaml"
    candidate_path.write_text(_to_yaml(candidate_with_new_deny), encoding="utf-8")

    rc_fail = cli.main([
        "policy", "simulate", str(candidate_path),
        "--against", str(history), "--fail-on-new-blocks",
    ])
    assert rc_fail == 1

    candidate_no_change = _to_yaml(_base_policy_dict())
    candidate_path2 = tmp_path / "candidate2.yaml"
    candidate_path2.write_text(candidate_no_change, encoding="utf-8")

    rc_ok = cli.main([
        "policy", "simulate", str(candidate_path2),
        "--against", str(history), "--fail-on-new-blocks",
    ])
    assert rc_ok == 0


def test_simulate_never_writes_to_audit_log_or_active_policy(
    tmp_path: Path, history: Path, capsys
) -> None:
    """Regression: simulate is read-only start to finish."""
    audit_before = history.read_bytes()

    candidate_path = tmp_path / "candidate.yaml"
    candidate_dict = _base_policy_dict()
    candidate_path.write_text(_to_yaml(candidate_dict), encoding="utf-8")
    candidate_before = candidate_path.read_bytes()

    active_policy_path = tmp_path / "govern.yaml"
    active_policy_path.write_text(_to_yaml(_base_policy_dict()), encoding="utf-8")
    active_before = active_policy_path.read_bytes()

    rc = cli.main([
        "-p", str(active_policy_path),
        "policy", "simulate", str(candidate_path), "--against", str(history),
    ])
    capsys.readouterr()

    assert rc == 0
    assert history.read_bytes() == audit_before
    assert candidate_path.read_bytes() == candidate_before
    assert active_policy_path.read_bytes() == active_before


def _to_yaml(d: dict) -> str:
    import yaml
    return yaml.safe_dump(d)
