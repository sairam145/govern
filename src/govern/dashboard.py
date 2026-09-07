"""Read-only monitoring dashboard for the audit log.

A small FastAPI app: a JSON API over `.govern/audit.jsonl` plus a single
static HTML page that polls it. Nothing here ever opens the audit log for
writing — Governor._record() owns that, this module only tails it.

fastapi/uvicorn are an optional extra (`pip install govern-agent[dashboard]`);
this module is only imported from `cli.cmd_dashboard`, never at package
import time.
"""

from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse

from .collusion import replay
from .engine import default_audit_path
from .fleet import build_fleet, read_entries
from .policy import Policy

STATIC_DIR = Path(__file__).parent / "static"


def create_app(audit_log: Optional[Path] = None, policy: Optional[Policy] = None) -> FastAPI:
    """Build the dashboard app, bound to one audit log path."""
    path = Path(audit_log) if audit_log else default_audit_path()
    active_policy = policy or Policy.discover()
    app = FastAPI(title="govern dashboard")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "dashboard.html")

    @app.get("/api/events")
    def get_events(
        agent_id: Optional[str] = None,
        effect: Optional[str] = None,
        offset: int = 0,
        limit: int = Query(50, le=500),
    ) -> Dict[str, Any]:
        entries = list(read_entries(path))
        entries.sort(key=lambda e: e.get("timestamp") or 0, reverse=True)
        if agent_id:
            entries = [e for e in entries if e.get("agent_id") == agent_id]
        if effect:
            entries = [e for e in entries if e.get("effect") == effect]
        return {
            "total": len(entries),
            "offset": offset,
            "limit": limit,
            "events": entries[offset:offset + limit],
        }

    @app.get("/api/agents")
    def get_agents() -> Dict[str, Any]:
        fleet = build_fleet(path)
        return {
            "agents": [
                {
                    "agent_id": rec.agent_id,
                    "total_actions": rec.total,
                    # allowed/blocked reflect the real outcome of each call —
                    # a require_approval effect that was granted counts as
                    # allowed, one that was refused (or never had a handler)
                    # counts as blocked. require_approval/approvals_* below
                    # make the approval gate itself visible as its own
                    # dimension, since two require_approval events for the
                    # same agent can legitimately land in different buckets
                    # if a real approval handler grants one and refuses
                    # another.
                    "allowed": rec.total - rec.blocked,
                    "blocked": rec.blocked,
                    "require_approval": rec.require_approval_total,
                    "approvals_granted": rec.approvals_granted,
                    "approvals_refused": rec.approvals_refused,
                    "last_seen": rec.last_seen,
                }
                for rec in sorted(fleet.values(), key=lambda r: r.agent_id)
            ]
        }

    @app.get("/api/stats")
    def get_stats(since_hours: float = 24.0, bucket_minutes: float = 60.0) -> Dict[str, Any]:
        cutoff = time.time() - since_hours * 3600
        bucket_seconds = bucket_minutes * 60
        buckets: Dict[int, Dict[str, int]] = defaultdict(lambda: {"allowed": 0, "blocked": 0})

        for entry in read_entries(path):
            if entry.get("alert_type"):
                continue  # not a per-call decision, doesn't fit allowed/blocked
            ts = float(entry.get("timestamp") or 0)
            if ts < cutoff:
                continue
            bucket = int(ts // bucket_seconds * bucket_seconds)
            metadata = entry.get("metadata") or {}
            was_blocked = (not entry.get("allowed")) or metadata.get("would_have_blocked")
            buckets[bucket]["blocked" if was_blocked else "allowed"] += 1

        return {
            "since_hours": since_hours,
            "bucket_minutes": bucket_minutes,
            "buckets": [{"timestamp": ts, **counts} for ts, counts in sorted(buckets.items())],
        }

    @app.get("/api/cross-agent")
    def get_cross_agent(since_hours: float = 24.0) -> Dict[str, Any]:
        """Cross-agent activity: raw counts, plus actual triggered alerts.

        `groups` is unscored aggregation — action counts by (resource,
        environment) across every agent_id in the window, with no rule
        attached to any of it. `alerts` is different in kind: it's
        active_alerts() from a CollusionDetector replayed against the
        real audit log using the active policy's aggregate_rules — a
        group only appears there if a configured rule's threshold is
        actually crossed, not just because multiple agents touched the
        same resource.
        """
        cutoff = time.time() - since_hours * 3600
        groups: Dict[tuple, Dict[str, Any]] = {}

        for entry in read_entries(path):
            if entry.get("alert_type"):
                continue
            ts = float(entry.get("timestamp") or 0)
            if ts < cutoff:
                continue
            key = (entry.get("resource", "*"), entry.get("environment", "unknown"))
            group = groups.setdefault(
                key,
                {"resource": key[0], "environment": key[1], "count": 0, "agent_ids": set()},
            )
            group["count"] += 1
            group["agent_ids"].add(entry.get("agent_id", "unnamed-agent"))

        detector = replay(path, active_policy.aggregate_rules)

        return {
            "since_hours": since_hours,
            "groups": [
                {**g, "agent_ids": sorted(g["agent_ids"]), "distinct_agents": len(g["agent_ids"])}
                for g in sorted(groups.values(), key=lambda g: -g["count"])
            ],
            "alerts": detector.active_alerts(),
        }

    return app
