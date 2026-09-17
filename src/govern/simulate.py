"""Policy simulation: replay recorded history through a candidate policy.

Reuses Policy.evaluate() — the exact same precedence logic (deny beats
require_approval beats allow) that Governor.evaluate() calls in
production — so a simulated outcome can never drift from what real
enforcement would actually do. This module never touches Governor, an
approval handler, or the audit log for writing: it is read-only,
start to finish.

A require_approval outcome is reported as its own effect string, not
resolved into allow/deny — nothing here can honestly know how a live
approval call would go for a hypothetical replay, and collapsing it into
a boolean would misrepresent an unresolved case as a resolved one (the
same mistake the dashboard's /api/agents aggregation used to make).

PHASE 1 LIMITATION: Chain rules are NOT evaluated in simulate. Chains are
in-memory per-Governor-instance; simulate creates fresh instances replaying
JSONL, so chain context is lost. Only per-call rules and aggregate_rules
are replayed. Phase 2 will add persistent chains + simulate integration.
See CLAUDE.md for details.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .collusion import CollusionDetector
from .fleet import read_entries
from .policy import Policy


@dataclass
class ChangedEvent:
    timestamp: float
    agent_id: str
    action: str
    resource: str
    environment: str
    old_effect: str
    old_allowed: bool
    new_effect: str
    new_rule_id: Optional[str]
    new_severity: str

    @property
    def is_new_denial(self) -> bool:
        return self.new_effect == "deny" and self.old_effect != "deny"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "environment": self.environment,
            "old_effect": self.old_effect,
            "old_allowed": self.old_allowed,
            "new_effect": self.new_effect,
            "new_rule_id": self.new_rule_id,
            "new_severity": self.new_severity,
        }


@dataclass
class SimulationResult:
    policy_source: str
    audit_source: str
    since_hours: Optional[float]
    total_events: int
    changed: List[ChangedEvent] = field(default_factory=list)
    # aggregate_rules that would have newly crossed threshold against this
    # history, from replaying the real CollusionDetector — empty if the
    # candidate policy has no aggregate_rules or none of them trip.
    collusion_alerts: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def unchanged_count(self) -> int:
        return self.total_events - len(self.changed)

    @property
    def new_denials(self) -> List[ChangedEvent]:
        return [c for c in self.changed if c.is_new_denial]


def simulate(
    policy: Policy,
    audit_log: Path,
    since_hours: Optional[float] = None,
) -> SimulationResult:
    """Replay every event in audit_log through `policy`, read-only.

    Never writes to audit_log, never mutates policy, never calls an
    approval handler. Also replays through a fresh CollusionDetector
    built from policy.aggregate_rules — the exact same class live
    enforcement uses, not a separate simulation-only implementation.
    The detector's window math is relative to each event's own
    timestamp, not wall-clock time, so replaying history in
    chronological order (which read_entries naturally is, since the log
    is append-only) is exactly as correct as feeding it live.
    """
    cutoff = time.time() - since_hours * 3600 if since_hours else None
    total = 0
    changed: List[ChangedEvent] = []
    detector = CollusionDetector(policy.aggregate_rules)
    triggered: Dict[tuple, Any] = {}

    for entry in read_entries(audit_log):
        if entry.get("alert_type"):
            continue  # our own annotations aren't replayable decisions
        ts = float(entry.get("timestamp") or 0)
        if cutoff and ts < cutoff:
            continue
        total += 1

        action = entry.get("action", "")
        resource = entry.get("resource", "*")
        environment = entry.get("environment", "unknown")
        old_effect = entry.get("effect", "allow")

        new_effect, new_rule = policy.evaluate(action, resource, environment)
        if new_effect != old_effect:
            changed.append(ChangedEvent(
                timestamp=ts,
                agent_id=entry.get("agent_id", "unnamed-agent"),
                action=action,
                resource=resource,
                environment=environment,
                old_effect=old_effect,
                old_allowed=bool(entry.get("allowed")),
                new_effect=new_effect,
                new_rule_id=(new_rule.id if new_rule else None),
                new_severity=(new_rule.severity if new_rule else "medium"),
            ))

        for result in detector.record(entry):
            if result.triggered:
                key = (result.rule_id, result.resource, result.environment)
                triggered[key] = result  # keep the latest/peak snapshot

    collusion_alerts = [
        r.to_dict() for r in sorted(triggered.values(), key=lambda r: -r.count)
    ]

    return SimulationResult(
        policy_source=policy.source,
        audit_source=str(audit_log),
        since_hours=since_hours,
        total_events=total,
        changed=changed,
        collusion_alerts=collusion_alerts,
    )


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "unknown"


def render_table(result: SimulationResult, diff_only: bool = False) -> None:
    print(f"policy simulate  {result.policy_source}")
    print(f"  against:  {result.audit_source}")
    since = f"last {result.since_hours:g}h" if result.since_hours else "all history"
    print(f"  since:    {since}\n")

    if not result.changed and not result.collusion_alerts:
        print(f"no change — all {result.total_events} event(s) would produce the same outcome")
        return

    if result.changed:
        print(f"CHANGED OUTCOMES ({len(result.changed)})")
        for c in sorted(result.changed, key=lambda c: c.timestamp):
            print(f"  {c.old_effect.upper()} -> {c.new_effect.upper()}   "
                  f"{c.action} -> {c.resource}   agent={c.agent_id}   {_fmt_ts(c.timestamp)}")
            print(f"      new rule: {c.new_rule_id or '(default_effect)'} [{c.new_severity}]")
    else:
        print("no per-call outcome changes")

    if not diff_only:
        print(f"\n  {result.unchanged_count} unchanged event(s) (same outcome as recorded)")

        if result.new_denials:
            print(f"\n  new denials introduced: {len(result.new_denials)}  "
                  f"(see --fail-on-new-blocks)")

    if result.collusion_alerts:
        print("\nNEW COLLUSION ALERTS")
        for alert in result.collusion_alerts:
            print(f"  {alert['effect'].upper()}  {alert['rule_id']}   "
                  f"{alert['resource']} ({alert['environment']})")
            print(f"      {alert['count']}/{alert['threshold']} {alert['threshold_type']}"
                  f"   agents: {', '.join(alert['agent_ids'])}")


def to_dict(result: SimulationResult) -> Dict[str, Any]:
    return {
        "apiVersion": "govern/v1",
        "kind": "PolicySimulation",
        "policy_source": result.policy_source,
        "against": result.audit_source,
        "since_hours": result.since_hours,
        "summary": {
            "total_events": result.total_events,
            "changed": len(result.changed),
            "unchanged": result.unchanged_count,
            "new_denials": len(result.new_denials),
        },
        "changed_events": [c.to_dict() for c in sorted(result.changed, key=lambda c: c.timestamp)],
        "collusion_alerts": result.collusion_alerts,
    }
