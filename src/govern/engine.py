"""The governance engine.

A Governor holds a policy, an identity (agent + environment), an
enforcement mode, and an append-only audit log. Everything else in the
package is a way of getting calls to land here.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .chain import ChainRegistry
from .collusion import CollusionDetector
from .decision import Decision, PolicyViolation
from .policy import Policy

MODES = ("enforce", "monitor")

_COLLUSION_DETECTOR: Optional[CollusionDetector] = None


def default_audit_path() -> Path:
    env = os.environ.get("GOVERN_AUDIT_LOG")
    if env:
        return Path(env)
    return Path.cwd() / ".govern" / "audit.jsonl"


def _shared_collusion_detector(aggregate_rules) -> CollusionDetector:
    """One CollusionDetector per process, shared across every Governor.

    Cross-agent detection only means something if agents share state — a
    single agent's own Governor never sees another agent's calls, and
    each govern.init() call would otherwise wipe out what the previous
    agent contributed. Rule *definitions* are refreshed on every init()
    (last writer wins if two agents in one process run different
    policies); the sliding-window state itself survives, since it
    belongs to the wall-clock activity, not to any one session.
    """
    global _COLLUSION_DETECTOR
    if _COLLUSION_DETECTOR is None:
        _COLLUSION_DETECTOR = CollusionDetector(aggregate_rules)
    else:
        _COLLUSION_DETECTOR.set_rules(aggregate_rules)
    return _COLLUSION_DETECTOR


def reset_collusion_detector() -> None:
    """Drop all in-memory collusion state. Mainly for tests and process restarts."""
    global _COLLUSION_DETECTOR
    _COLLUSION_DETECTOR = None


def deny_approval(decision: Decision) -> bool:
    """Default approval handler: no human present, so no approval."""
    return False


def prompt_approval(decision: Decision) -> bool:
    """Interactive approval handler for CLI-driven agents."""
    if not sys.stdin.isatty():
        return False
    print(f"\n  approval required: {decision.action} on {decision.resource}")
    print(f"  rule: {decision.rule_id} (severity: {decision.severity})")
    answer = input("  allow this action? [y/N] ").strip().lower()
    return answer in ("y", "yes")


class Governor:
    def __init__(
        self,
        agent_id: str = "unnamed-agent",
        environment: str = "development",
        policy: Optional[Policy] = None,
        mode: str = "enforce",
        approval: Optional[Callable[[Decision], bool]] = None,
        audit_log: Optional[os.PathLike | str] = None,
        quiet: bool = False,
    ):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got '{mode}'")
        self.agent_id = agent_id
        self.environment = environment
        self.policy = policy or Policy.discover()
        self.mode = mode
        self.approval = approval or deny_approval
        self.audit_log = Path(audit_log) if audit_log else default_audit_path()
        self.quiet = quiet
        self.session_id = uuid.uuid4().hex[:12]
        self.started_at = time.time()
        self.decisions: list[Decision] = []
        self.collusion = _shared_collusion_detector(self.policy.aggregate_rules)
        self.chain = ChainRegistry()

    # -- core -------------------------------------------------------------

    def evaluate(
        self,
        action: str,
        resource: str = "*",
        metadata: Optional[Dict[str, Any]] = None,
        initiated_by: Optional[str] = None,
    ) -> Decision:
        """Decide, record, and return — never raises.

        Args:
            action: the action being evaluated (e.g., "s3:DeleteBucket")
            resource: what the action targets
            metadata: optional caller-provided metadata
            initiated_by: id of the parent ActionStep in this chain (None if root)

        Returns:
            Decision with allowed/blocked outcome
        """
        # Record this action in the chain
        step = self.chain.record_step(
            actor=self.agent_id,
            actor_type="agent",
            action=action,
            resource=resource,
            environment=self.environment,
            initiated_by=initiated_by,
        )

        effect, rule = self.policy.evaluate(action, resource, self.environment)

        decision = Decision(
            action=action,
            resource=resource,
            effect=effect,
            allowed=(effect == "allow"),
            reason=(rule.description if rule else f"no rule matched; default_effect={effect}"),
            rule_id=(rule.id if rule else None),
            severity=(rule.severity if rule else "medium"),
            mode=self.mode,
            agent_id=self.agent_id,
            environment=self.environment,
            session_id=self.session_id,
            metadata=metadata or {},
        )

        # Check chain-aware rules (after per-call rules, before aggregate rules)
        if self.policy.chain_rules:
            effect, rule = self._check_chain_rules(decision, step)
            if rule:
                decision.effect = effect
                decision.allowed = (effect == "allow")
                decision.rule_id = rule.id
                decision.severity = rule.severity
                decision.reason = rule.description or f"matched chain rule '{rule.id}'"

        if effect == "require_approval":
            approved = bool(self.approval(decision))
            decision.allowed = approved
            decision.metadata["approval"] = "granted" if approved else "refused"
            decision.reason = (
                f"{decision.reason} (human approval {decision.metadata['approval']})"
            )

        for result in self.collusion.record(decision.to_dict()):
            if not result.triggered:
                continue
            if result.effect == "deny":
                original = {
                    "effect": decision.effect,
                    "allowed": decision.allowed,
                    "rule_id": decision.rule_id,
                }
                decision.metadata["per_call_decision"] = original
                decision.metadata["aggregate_rule"] = result.to_dict()
                decision.allowed = False
                decision.effect = "deny"
                decision.rule_id = result.rule_id
                decision.severity = "critical"
                decision.reason = (
                    f"per-call policy result was '{original['effect']}' "
                    f"({'allowed' if original['allowed'] else 'blocked'}), but aggregate "
                    f"rule '{result.rule_id}' crossed threshold ({result.count}/"
                    f"{result.threshold} {result.threshold_type} within window; "
                    f"agents involved: {', '.join(result.agent_ids)})"
                )
            elif result.effect == "alert":
                self._record_collusion_alert(result)

        if self.mode == "monitor" and not decision.allowed:
            decision.metadata["would_have_blocked"] = True
            decision.allowed = True

        self._record(decision)
        return decision

    def enforce(
        self,
        action: str,
        resource: str = "*",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """Evaluate and raise PolicyViolation if the action is not allowed."""
        decision = self.evaluate(action, resource, metadata)
        if not decision.allowed:
            raise PolicyViolation(decision)
        return decision

    # -- reporting --------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        blocked = [d for d in self.decisions if not d.allowed or d.metadata.get("would_have_blocked")]
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "environment": self.environment,
            "mode": self.mode,
            "policy": self.policy.source,
            "duration_seconds": round(time.time() - self.started_at, 3),
            "actions_evaluated": len(self.decisions),
            "actions_blocked": len(blocked),
            "blocked": [
                {"action": d.action, "resource": d.resource, "rule_id": d.rule_id, "severity": d.severity}
                for d in blocked
            ],
        }

    # -- internals --------------------------------------------------------

    def _check_chain_rules(self, decision: Decision, step) -> tuple:
        """Check chain-aware rules against the action sequence.

        Returns: (effect, rule) if a chain rule matched, else (current effect, None).
        Precedence: deny > require_approval > allow (same as per-call rules).
        """
        from .policy import PRECEDENCE

        best_effect = decision.effect
        best_rule = None
        best_precedence = PRECEDENCE.get(best_effect, 0)

        for chain_rule in self.policy.chain_rules:
            # First, check this action matches the rule's pattern
            if not chain_rule.matches(decision.action, decision.resource, decision.environment):
                continue

            # If the rule has an if_previous condition, check the chain history
            if chain_rule.if_previous:
                if not self._check_previous_condition(chain_rule.if_previous, step):
                    continue

            # This rule matches; compare with best so far using precedence
            rule_precedence = PRECEDENCE.get(chain_rule.effect, 0)
            if rule_precedence > best_precedence:
                best_effect = chain_rule.effect
                best_rule = chain_rule
                best_precedence = rule_precedence

        return (best_effect, best_rule)

    def _check_previous_condition(self, if_previous: Dict[str, str], current_step) -> bool:
        """Check if a previous action matching the condition occurred recently.

        Args:
            if_previous: {"action": "pattern", "within": "5m"}
            current_step: the ActionStep we're evaluating

        Returns:
            True if a matching previous action is found within the window.
        """
        from fnmatch import fnmatch
        from .policy import parse_duration

        action_pattern = if_previous.get("action", "")
        within_raw = if_previous.get("within", "")
        if not action_pattern or not within_raw:
            return False

        try:
            within_seconds = parse_duration(within_raw)
        except Exception:
            return False

        # Get the chain leading up to this step
        chain = self.chain.reconstruct_chain_from(current_step)

        # Look backwards through the chain for a matching action
        current_time = time.time()
        cutoff_time = current_time - within_seconds

        for step in reversed(chain[:-1]):  # exclude the current step
            if step.timestamp < cutoff_time:
                break  # outside the window
            if fnmatch(step.action.lower(), action_pattern.lower()):
                return True

        return False

    def _append(self, payload: Dict[str, Any]) -> None:
        try:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, default=str) + "\n")
        except OSError:
            # An unwritable audit log must never take the agent down.
            pass

    def _record(self, decision: Decision) -> None:
        self.decisions.append(decision)
        if not self.quiet:
            marker = "ALLOW " if decision.allowed else "BLOCK "
            if decision.metadata.get("would_have_blocked"):
                marker = "WOULD-BLOCK "
            print(f"[govern] {marker}{decision.action} -> {decision.resource}"
                  f"{f' ({decision.rule_id})' if decision.rule_id else ''}")
        self._append(decision.to_dict())

    def _record_collusion_alert(self, result) -> None:
        alert = {
            "alert_type": "collusion",
            "effect": "collusion_alert",
            "rule_id": result.rule_id,
            "resource": result.resource,
            "environment": result.environment,
            "threshold_type": result.threshold_type,
            "count": result.count,
            "threshold": result.threshold,
            "agent_ids": result.agent_ids,
            "session_id": self.session_id,
            "timestamp": time.time(),
        }
        if not self.quiet:
            print(f"[govern] COLLUSION ALERT  {result.rule_id}  {result.resource}"
                  f"  {result.count}/{result.threshold} {result.threshold_type}"
                  f"  agents={','.join(result.agent_ids)}")
        self._append(alert)
