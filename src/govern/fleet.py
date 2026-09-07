"""The fleet view.

Reads the audit log and rolls it up by agent. This is the first piece of
the thing that is actually worth paying for later: not "did this call get
blocked" but "what are all my agents doing, and which one is the problem."

Scope note: govern only knows about agents that have run through it.
There is no discovery here — an agent that never called govern does not
appear, because govern has never seen it.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class AgentRecord:
    agent_id: str
    environments: set = field(default_factory=set)
    sessions: set = field(default_factory=set)
    total: int = 0
    blocked: int = 0
    require_approval_total: int = 0
    approvals_granted: int = 0
    approvals_refused: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    modes: set = field(default_factory=set)
    rule_hits: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    worst_severity: str = "info"
    recent_blocks: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def risk_rate(self) -> float:
        return (self.blocked / self.total * 100) if self.total else 0.0


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def read_entries(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a truncated write must not break the report
    return entries


def build_fleet(
    path: Path,
    since_hours: Optional[float] = None,
    environment: Optional[str] = None,
) -> Dict[str, AgentRecord]:
    cutoff = time.time() - since_hours * 3600 if since_hours else None
    fleet: Dict[str, AgentRecord] = {}

    for entry in read_entries(path):
        ts = float(entry.get("timestamp") or 0)
        if cutoff and ts < cutoff:
            continue
        env = entry.get("environment", "unknown")
        if environment and env != environment:
            continue

        agent_id = entry.get("agent_id", "unnamed-agent")
        rec = fleet.setdefault(agent_id, AgentRecord(agent_id=agent_id))

        rec.environments.add(env)
        rec.sessions.add(entry.get("session_id", "?"))
        rec.modes.add(entry.get("mode", "enforce"))
        rec.total += 1
        rec.first_seen = min(rec.first_seen or ts, ts)
        rec.last_seen = max(rec.last_seen, ts)

        metadata = entry.get("metadata") or {}
        approval_outcome = metadata.get("approval")
        if approval_outcome is not None:
            # require_approval is a request classification, not an outcome —
            # the same rule can grant one call and refuse another for the
            # same agent, so allowed/blocked (below) stays the ground truth
            # while this makes the approval gate itself visible.
            rec.require_approval_total += 1
            if approval_outcome == "granted":
                rec.approvals_granted += 1
            else:
                rec.approvals_refused += 1

        was_blocked = (not entry.get("allowed")) or metadata.get("would_have_blocked")
        if was_blocked:
            rec.blocked += 1
            rule = entry.get("rule_id") or "(default_effect)"
            rec.rule_hits[rule] += 1
            severity = entry.get("severity", "info")
            if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(rec.worst_severity):
                rec.worst_severity = severity
            rec.recent_blocks.append({
                "timestamp": ts,
                "action": entry.get("action"),
                "resource": entry.get("resource"),
                "rule_id": rule,
                "severity": severity,
                "environment": env,
                "mode": entry.get("mode"),
            })

    for rec in fleet.values():
        rec.recent_blocks = sorted(rec.recent_blocks, key=lambda b: b["timestamp"])[-10:]
    return fleet


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    delta = time.time() - ts
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def render_table(fleet: Dict[str, AgentRecord], path: Path) -> None:
    if not fleet:
        print(f"No agents have reported to govern yet.\n")
        print(f"  audit log: {path}")
        print("  run `govern demo` to generate activity, then try again.")
        return

    agents = sorted(fleet.values(), key=lambda r: (-r.blocked, r.agent_id))

    print(f"\n{len(agents)} agent(s) seen  ·  {path}\n")
    header = f"{'AGENT':<26} {'ENV':<12} {'RUNS':>5} {'ACTIONS':>8} {'BLOCKED':>8} {'RISK':>7} {'WORST':<9} {'LAST SEEN':<10}"
    print(header)
    print("-" * len(header))

    for rec in agents:
        envs = ",".join(sorted(rec.environments))
        flag = " *" if rec.worst_severity == "critical" else ""
        print(
            f"{rec.agent_id[:26]:<26} {envs[:12]:<12} {len(rec.sessions):>5} "
            f"{rec.total:>8} {rec.blocked:>8} {rec.risk_rate:>6.0f}% "
            f"{rec.worst_severity:<9} {_ago(rec.last_seen):<10}{flag}"
        )

    total_actions = sum(r.total for r in agents)
    total_blocked = sum(r.blocked for r in agents)
    monitoring = [r.agent_id for r in agents if "monitor" in r.modes]

    print()
    print(f"  {total_actions} actions evaluated, {total_blocked} blocked "
          f"({total_blocked / total_actions * 100:.0f}%)" if total_actions else "")
    if monitoring:
        print(f"  monitor mode (nothing actually blocked): {', '.join(monitoring)}")

    all_rules: Dict[str, int] = defaultdict(int)
    for rec in agents:
        for rule, count in rec.rule_hits.items():
            all_rules[rule] += count
    if all_rules:
        print("\n  most-triggered rules:")
        for rule, count in sorted(all_rules.items(), key=lambda kv: -kv[1])[:5]:
            print(f"    {count:>4}x  {rule}")

    print("\n  govern agents --agent <name>   for detail")


def render_detail(rec: AgentRecord) -> None:
    print(f"\nagent: {rec.agent_id}")
    print(f"  environments:  {', '.join(sorted(rec.environments))}")
    print(f"  modes:         {', '.join(sorted(rec.modes))}")
    print(f"  sessions:      {len(rec.sessions)}")
    print(f"  actions:       {rec.total}")
    print(f"  blocked:       {rec.blocked} ({rec.risk_rate:.0f}%)")
    print(f"  require_approval hits: {rec.require_approval_total} "
          f"(granted: {rec.approvals_granted}, refused: {rec.approvals_refused})")
    print(f"  worst severity:    {rec.worst_severity}")
    print(f"  first seen:    {_ago(rec.first_seen)}")
    print(f"  last seen:     {_ago(rec.last_seen)}")

    if rec.rule_hits:
        print("\n  rules triggered:")
        for rule, count in sorted(rec.rule_hits.items(), key=lambda kv: -kv[1]):
            print(f"    {count:>4}x  {rule}")

    if rec.recent_blocks:
        print("\n  recent blocks:")
        for block in reversed(rec.recent_blocks):
            print(f"    [{block['severity']:<8}] {block['action']} -> {block['resource']}")
            print(f"               {block['rule_id']}  ({_ago(block['timestamp'])})")
    print()


def to_dicts(fleet: Dict[str, AgentRecord]) -> List[Dict[str, Any]]:
    """Plain per-agent dicts, sorted by agent_id — the shape both the old
    `govern agents --json` and the newer `govern agent list/inspect -o json`
    serialize, so there's exactly one definition of what an agent summary
    looks like as data."""
    payload = []
    for rec in sorted(fleet.values(), key=lambda r: r.agent_id):
        payload.append({
            "agent_id": rec.agent_id,
            "environments": sorted(rec.environments),
            "modes": sorted(rec.modes),
            "sessions": len(rec.sessions),
            "actions": rec.total,
            "blocked": rec.blocked,
            "risk_rate_pct": round(rec.risk_rate, 1),
            "require_approval_total": rec.require_approval_total,
            "approvals_granted": rec.approvals_granted,
            "approvals_refused": rec.approvals_refused,
            "worst_severity": rec.worst_severity,
            "first_seen": rec.first_seen,
            "last_seen": rec.last_seen,
            "rule_hits": dict(rec.rule_hits),
            "recent_blocks": rec.recent_blocks,
        })
    return payload


def to_json(fleet: Dict[str, AgentRecord]) -> str:
    return json.dumps(to_dicts(fleet), indent=2)
