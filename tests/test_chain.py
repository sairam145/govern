"""Tests for action chain reconstruction and chain-aware policy matching."""

import time
from pathlib import Path

import pytest

from govern.chain import ActionChain, ActionStep, ChainRegistry
from govern.engine import Governor
from govern.policy import ChainRule, Policy


def _base_policy_dict(chain_rule: dict) -> dict:
    return {
        "version": 1,
        "default_effect": "deny",
        "rules": [
            {"id": "allow-reads", "effect": "allow", "actions": ["*:Get*", "*:List*"]},
            {"id": "allow-writes", "effect": "allow", "actions": ["*:Put*", "*:Apply*"]},
            {"id": "allow-deletes", "effect": "allow", "actions": ["*:Delete*"]},
        ],
        "aggregate_rules": [],
        "chain_rules": [chain_rule],
    }


def _chain_rule(effect: str = "require_approval") -> dict:
    return {
        "id": "careful-after-terraform",
        "effect": effect,
        "description": "Require approval for deletes after terraform runs.",
        "actions": ["*:Delete*"],
        "resources": ["*"],
        "environments": ["production"],
        "if_previous": {"action": "terraform:*", "within": "5m"},
    }


# -- chain reconstruction ---------------------------------------------------


def test_chain_registry_records_and_retrieves_steps() -> None:
    registry = ChainRegistry()

    step1 = registry.record_step("alice", "human", "approve", "*", "production")
    assert step1.id
    assert step1.actor == "alice"
    assert step1.actor_type == "human"
    assert step1.initiated_by is None  # root

    step2 = registry.record_step("agent-a", "agent", "terraform:Apply", "state.db", "production", initiated_by=step1.id)
    assert step2.initiated_by == step1.id

    assert registry.get_step(step1.id) == step1
    assert registry.get_step(step2.id) == step2


def test_chain_reconstruction_follows_parent_links() -> None:
    registry = ChainRegistry()

    root = registry.record_step("alice", "human", "approve", "*", "production")
    agent_step = registry.record_step("agent-a", "agent", "terraform:Apply", "state.db", "production", initiated_by=root.id)
    delete_step = registry.record_step("agent-a", "agent", "s3:DeleteBucket", "backup", "production", initiated_by=agent_step.id)

    chain = registry.reconstruct_chain_from(delete_step)
    assert len(chain) == 3
    assert chain[0] == root
    assert chain[1] == agent_step
    assert chain[2] == delete_step


# -- chain-aware rule matching in live enforcement ---------------------------


def test_chain_aware_rule_triggers_when_previous_action_in_window(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_chain_rule(effect="require_approval")))
    audit_log = tmp_path / "audit.jsonl"

    gov = Governor(
        agent_id="agent-a",
        environment="production",
        policy=policy,
        quiet=True,
        audit_log=audit_log,
    )

    # Step 1: terraform apply (individually allowed)
    terraform_decision = gov.evaluate("terraform:Apply", "state.db")
    assert terraform_decision.allowed is True
    terraform_step_id = gov.chain.reconstruct_chain_from(
        gov.chain._steps[list(gov.chain._steps.keys())[-1]]
    )[-1].id

    # Step 2: s3 delete, initiated by terraform, within 5 minutes
    # Individually allowed by per-call rule, but chain-aware rule requires approval
    delete_decision = gov.evaluate("s3:DeleteBucket", "backup", initiated_by=terraform_step_id)
    assert delete_decision.allowed is False  # require_approval + no approval handler = denied
    assert delete_decision.rule_id == "careful-after-terraform"
    assert delete_decision.effect == "require_approval"


def test_chain_aware_rule_does_not_trigger_without_previous_action(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_chain_rule(effect="require_approval")))
    audit_log = tmp_path / "audit.jsonl"

    gov = Governor(
        agent_id="agent-a",
        environment="production",
        policy=policy,
        quiet=True,
        audit_log=audit_log,
    )

    # S3 delete without any prior terraform — should be allowed by per-call rule
    delete_decision = gov.evaluate("s3:DeleteBucket", "backup")
    assert delete_decision.allowed is True  # allow-deletes rule matches
    assert delete_decision.rule_id == "allow-deletes"


def test_chain_aware_rule_does_not_trigger_outside_window(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_chain_rule(effect="require_approval")))
    audit_log = tmp_path / "audit.jsonl"

    gov = Governor(
        agent_id="agent-a",
        environment="production",
        policy=policy,
        quiet=True,
        audit_log=audit_log,
    )

    # Manually create steps with a wide time gap
    from govern.chain import ActionStep

    old_terraform = ActionStep(
        id="old",
        actor="agent-a",
        actor_type="agent",
        action="terraform:Apply",
        resource="state.db",
        environment="production",
        timestamp=time.time() - 600,  # 10 minutes ago, outside the 5m window
    )
    gov.chain._steps["old"] = old_terraform
    gov.chain._chain.append(old_terraform)

    # Delete initiated by the old terraform step
    delete_decision = gov.evaluate("s3:DeleteBucket", "backup", initiated_by="old")
    assert delete_decision.allowed is True  # rule doesn't trigger (outside window)
    assert delete_decision.rule_id == "allow-deletes"


def test_chain_aware_rule_with_deny_effect_overrides_allow(tmp_path: Path) -> None:
    policy = Policy.from_dict(_base_policy_dict(_chain_rule(effect="deny")))
    audit_log = tmp_path / "audit.jsonl"

    gov = Governor(
        agent_id="agent-a",
        environment="production",
        policy=policy,
        quiet=True,
        audit_log=audit_log,
    )

    terraform_decision = gov.evaluate("terraform:Apply", "state.db")
    terraform_step_id = gov.chain.reconstruct_chain_from(
        gov.chain._steps[list(gov.chain._steps.keys())[-1]]
    )[-1].id

    # Delete after terraform, with deny effect
    delete_decision = gov.evaluate("s3:DeleteBucket", "backup", initiated_by=terraform_step_id)
    assert delete_decision.allowed is False
    assert delete_decision.rule_id == "careful-after-terraform"
    assert delete_decision.effect == "deny"


def test_chain_aware_rule_precedence_deny_over_require_approval(tmp_path: Path) -> None:
    # Two rules: one requires approval, one denies
    rules_dict = _base_policy_dict(_chain_rule(effect="require_approval"))
    rules_dict["chain_rules"].append({
        "id": "absolutely-deny",
        "effect": "deny",
        "description": "Never allow this after terraform.",
        "actions": ["*:Delete*"],
        "resources": ["critical-*"],
        "environments": ["production"],
        "if_previous": {"action": "terraform:*", "within": "5m"},
    })

    policy = Policy.from_dict(rules_dict)
    audit_log = tmp_path / "audit.jsonl"

    gov = Governor(
        agent_id="agent-a",
        environment="production",
        policy=policy,
        quiet=True,
        audit_log=audit_log,
    )

    terraform_decision = gov.evaluate("terraform:Apply", "state.db")
    terraform_step_id = gov.chain.reconstruct_chain_from(
        gov.chain._steps[list(gov.chain._steps.keys())[-1]]
    )[-1].id

    # Delete of critical resource — deny effect wins
    delete_decision = gov.evaluate("s3:DeleteBucket", "critical-backup", initiated_by=terraform_step_id)
    assert delete_decision.effect == "deny"  # deny precedence wins
    assert delete_decision.rule_id == "absolutely-deny"


def test_empty_chain_rules_is_a_no_op(tmp_path: Path) -> None:
    """Empty chain_rules should not change behavior of existing per-call rules."""
    policy = Policy.bundled_default()
    audit_log = tmp_path / "audit.jsonl"
    gov = Governor(agent_id="agent-a", environment="production", policy=policy, quiet=True, audit_log=audit_log)

    # Verify no chain rules are set
    assert gov.policy.chain_rules == []

    # Existing behavior: allow-reads should work
    decision = gov.evaluate("s3:ListBuckets", "prod-billing")
    assert decision.allowed is True

    # Existing behavior: deny-destructive should block
    decision = gov.evaluate("s3:DeleteBucket", "prod-billing")
    assert decision.allowed is False
    assert decision.rule_id == "deny-destructive-prod"
