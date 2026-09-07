"""Cross-agent aggregate policy checks.

A single govern.evaluate() call only ever sees one agent's request. Some
risks only show up in aggregate — five agents each reading a different
shard of a sensitive dataset, none crossing any per-agent limit, but the
union reconstructing full access. aggregate_rules (policy.py) describe
that shape of risk; CollusionDetector is what actually tracks it, using
the exact same glob matching (AggregateRule.matches, backed by
policy._glob_any) that a regular Rule uses — no separate matching logic.

State here is in-memory and per-process only: a sliding window of recent
events per (rule, resource, environment) key, evicted as it ages out. It
resets on restart. The audit log remains the source of truth for what
happened; this is scratch state for deciding what to do right now, and
can always be rebuilt by replaying the log within a rule's window — see
`replay()` below, used by the dashboard and `govern policy simulate`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .policy import AggregateRule


@dataclass
class _WindowEvent:
    agent_id: str
    timestamp: float


@dataclass
class _AggregateState:
    rule: AggregateRule
    resource: str
    environment: str
    events: List[_WindowEvent] = field(default_factory=list)

    def evict(self, now: float) -> None:
        cutoff = now - self.rule.window_seconds
        self.events = [e for e in self.events if e.timestamp >= cutoff]

    @property
    def distinct_agents(self) -> int:
        return len({e.agent_id for e in self.events})

    @property
    def total_calls(self) -> int:
        return len(self.events)

    @property
    def current_count(self) -> int:
        if self.rule.threshold_type == "distinct_agents":
            return self.distinct_agents
        return self.total_calls

    @property
    def agent_ids(self) -> List[str]:
        return sorted({e.agent_id for e in self.events})

    @property
    def first_seen(self) -> float:
        return min((e.timestamp for e in self.events), default=0.0)

    @property
    def last_seen(self) -> float:
        return max((e.timestamp for e in self.events), default=0.0)


@dataclass
class CollusionResult:
    rule_id: str
    resource: str
    environment: str
    effect: str
    threshold_type: str
    triggered: bool
    count: int
    threshold: int
    agent_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "resource": self.resource,
            "environment": self.environment,
            "effect": self.effect,
            "threshold_type": self.threshold_type,
            "count": self.count,
            "threshold": self.threshold,
            "agent_ids": self.agent_ids,
        }


class CollusionDetector:
    """Tracks aggregate_rules across agents. A no-op if none are configured."""

    def __init__(self, aggregate_rules: Optional[Sequence[AggregateRule]] = None):
        self.rules: List[AggregateRule] = list(aggregate_rules or [])
        self._state: Dict[tuple, _AggregateState] = {}

    def set_rules(self, aggregate_rules: Sequence[AggregateRule]) -> None:
        """Swap in new rule definitions without discarding accumulated
        window state — a rule with the same id keeps its history."""
        self.rules = list(aggregate_rules or [])
        rules_by_id = {r.id: r for r in self.rules}
        for state in self._state.values():
            if state.rule.id in rules_by_id:
                state.rule = rules_by_id[state.rule.id]

    def record(self, event: Dict[str, Any]) -> List[CollusionResult]:
        """Feed one audit-shaped event in. Returns a result per matched rule.

        Eviction uses the event's own timestamp, not wall-clock time, so
        this is equally correct fed live (timestamps ~= now) or replayed
        from history in chronological order (timestamps in the past) —
        see simulate.py and replay() below.
        """
        if not self.rules:
            return []

        action = event.get("action", "")
        resource = event.get("resource", "*")
        environment = event.get("environment", "unknown")
        agent_id = event.get("agent_id", "unnamed-agent")
        timestamp = float(event.get("timestamp") or time.time())

        results: List[CollusionResult] = []
        for rule in self.rules:
            if not rule.matches(action, resource, environment):
                continue

            key = (rule.id, resource, environment)
            state = self._state.setdefault(
                key, _AggregateState(rule=rule, resource=resource, environment=environment)
            )
            state.evict(timestamp)
            state.events.append(_WindowEvent(agent_id=agent_id, timestamp=timestamp))
            state.evict(timestamp)

            count = state.current_count
            results.append(CollusionResult(
                rule_id=rule.id,
                resource=resource,
                environment=environment,
                effect=rule.effect,
                threshold_type=rule.threshold_type,
                triggered=count >= rule.threshold_max,
                count=count,
                threshold=rule.threshold_max,
                agent_ids=state.agent_ids,
            ))
        return results

    def active_alerts(self) -> List[Dict[str, Any]]:
        """Every (rule, resource, environment) currently at or over
        threshold, evaluated as of now. Only reports rules in the
        *current* ruleset, so a rule removed via set_rules() can't leave
        a stale alert behind."""
        now = time.time()
        current_ids = {r.id for r in self.rules}
        alerts = []
        for state in self._state.values():
            if state.rule.id not in current_ids:
                continue
            state.evict(now)
            if not state.events:
                continue
            if state.current_count >= state.rule.threshold_max:
                alerts.append({
                    "rule_id": state.rule.id,
                    "description": state.rule.description,
                    "effect": state.rule.effect,
                    "resource": state.resource,
                    "environment": state.environment,
                    "threshold_type": state.rule.threshold_type,
                    "count": state.current_count,
                    "threshold": state.rule.threshold_max,
                    "agent_ids": state.agent_ids,
                    "first_seen": state.first_seen,
                    "last_seen": state.last_seen,
                })
        return sorted(alerts, key=lambda a: -a["count"])


def replay(path: Path, aggregate_rules: Sequence[AggregateRule]) -> CollusionDetector:
    """Rebuild detector state by replaying the audit log.

    For anything without a live Governor's in-memory state — the
    dashboard, a restarted process. Bounded by the largest configured
    window so ancient history can't leak into "currently active."
    """
    from .fleet import read_entries

    detector = CollusionDetector(aggregate_rules)
    if not aggregate_rules:
        return detector

    max_window = max(r.window_seconds for r in aggregate_rules)
    cutoff = time.time() - max_window
    entries = sorted(read_entries(path), key=lambda e: e.get("timestamp") or 0)
    for entry in entries:
        if entry.get("alert_type"):
            continue  # our own annotations aren't replayable decisions
        ts = float(entry.get("timestamp") or 0)
        if ts < cutoff:
            continue
        detector.record(entry)
    return detector
