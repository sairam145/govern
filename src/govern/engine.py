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

    # -- core -------------------------------------------------------------

    def evaluate(
        self,
        action: str,
        resource: str = "*",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """Decide, record, and return — never raises."""
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
