"""Policy as data.

Rules live in a YAML file the customer can edit and version-control.
No policy logic is hardcoded in Python — the engine only knows how to
match and how to resolve precedence.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

EFFECTS = ("allow", "deny", "require_approval")
SEVERITIES = ("info", "low", "medium", "high", "critical")
AGGREGATE_EFFECTS = ("alert", "deny")
THRESHOLD_TYPES = ("distinct_agents", "total_calls")

# deny wins over require_approval wins over allow
PRECEDENCE = {"deny": 3, "require_approval": 2, "allow": 1}

DEFAULT_POLICY_FILENAMES = ("govern.yaml", "govern.yml", ".govern.yaml")

_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class PolicyError(Exception):
    """Raised when a policy file is malformed."""


def parse_duration(value: str) -> float:
    """"30s" -> 30.0, "10m" -> 600.0, "1h" -> 3600.0, "7d" -> 604800.0.

    A shared parser for anything that needs a human-writable time window —
    today that's the CLI's `policy simulate --since`; a future aggregate
    rule's `window` field should reuse this rather than growing a second
    duration parser.
    """
    match = _DURATION_RE.match(str(value).strip().lower())
    if not match:
        raise PolicyError(f"invalid duration '{value}'; expected e.g. '30s', '10m', '1h', '7d'")
    amount, unit = match.groups()
    return float(amount) * _DURATION_UNITS[unit]


def _as_tuple(value: Any, fallback: Sequence[str] = ("*",)) -> tuple:
    if value is None:
        return tuple(fallback)
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    actions: tuple = ("*",)
    resources: tuple = ("*",)
    environments: tuple = ("*",)
    severity: str = "medium"
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], index: int) -> "Rule":
        if not isinstance(raw, dict):
            raise PolicyError(f"rule #{index} is not a mapping")
        effect = str(raw.get("effect", "")).lower()
        if effect not in EFFECTS:
            raise PolicyError(
                f"rule '{raw.get('id', index)}' has effect '{effect}'; "
                f"expected one of {', '.join(EFFECTS)}"
            )
        severity = str(raw.get("severity", "medium")).lower()
        if severity not in SEVERITIES:
            raise PolicyError(
                f"rule '{raw.get('id', index)}' has severity '{severity}'; "
                f"expected one of {', '.join(SEVERITIES)}"
            )
        return cls(
            id=str(raw.get("id", f"rule-{index}")),
            effect=effect,
            actions=_as_tuple(raw.get("actions")),
            resources=_as_tuple(raw.get("resources")),
            environments=_as_tuple(raw.get("environments")),
            severity=severity,
            description=str(raw.get("description", "")),
        )

    def matches(self, action: str, resource: str, environment: str) -> bool:
        return (
            _glob_any(action, self.actions)
            and _glob_any(resource, self.resources)
            and _glob_any(environment, self.environments)
        )


def _glob_any(value: str, patterns: Sequence[str]) -> bool:
    value = (value or "").lower()
    return any(fnmatch(value, str(p).lower()) for p in patterns)


@dataclass(frozen=True)
class AggregateRule:
    """A cross-agent check: N distinct agents, or N total calls, against
    matching actions/resources/environments within a rolling window.

    Matched the same way as Rule (glob semantics via _glob_any); the
    difference is what triggers it — a count over time across possibly
    many agents, not a single call. See collusion.CollusionDetector for
    the actual window/threshold tracking.
    """

    id: str
    effect: str  # alert | deny
    actions: tuple = ("*",)
    resources: tuple = ("*",)
    environments: tuple = ("*",)
    window_seconds: float = 3600.0
    threshold_type: str = "distinct_agents"
    threshold_max: int = 1
    description: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], index: int) -> "AggregateRule":
        if not isinstance(raw, dict):
            raise PolicyError(f"aggregate_rules #{index} is not a mapping")
        rule_id = str(raw.get("id", f"aggregate-rule-{index}"))

        effect = str(raw.get("effect", "")).lower()
        if effect not in AGGREGATE_EFFECTS:
            raise PolicyError(
                f"aggregate rule '{rule_id}' has effect '{effect}'; "
                f"expected one of {', '.join(AGGREGATE_EFFECTS)}"
            )

        window_raw = raw.get("window")
        if not window_raw:
            raise PolicyError(f"aggregate rule '{rule_id}' is missing 'window'")

        threshold = raw.get("threshold")
        if not isinstance(threshold, dict):
            raise PolicyError(f"aggregate rule '{rule_id}' has no 'threshold' mapping")
        threshold_type = str(threshold.get("type", "")).lower()
        if threshold_type not in THRESHOLD_TYPES:
            raise PolicyError(
                f"aggregate rule '{rule_id}' has threshold type '{threshold_type}'; "
                f"expected one of {', '.join(THRESHOLD_TYPES)}"
            )
        try:
            threshold_max = int(threshold.get("max"))
        except (TypeError, ValueError):
            raise PolicyError(f"aggregate rule '{rule_id}' threshold.max must be an integer")

        return cls(
            id=rule_id,
            effect=effect,
            actions=_as_tuple(raw.get("actions")),
            resources=_as_tuple(raw.get("resources")),
            environments=_as_tuple(raw.get("environments")),
            window_seconds=parse_duration(window_raw),
            threshold_type=threshold_type,
            threshold_max=threshold_max,
            description=str(raw.get("description", "")),
        )

    def matches(self, action: str, resource: str, environment: str) -> bool:
        return (
            _glob_any(action, self.actions)
            and _glob_any(resource, self.resources)
            and _glob_any(environment, self.environments)
        )


@dataclass
class Policy:
    rules: List[Rule] = field(default_factory=list)
    aggregate_rules: List[AggregateRule] = field(default_factory=list)
    version: int = 1
    default_effect: str = "deny"
    source: str = "<inline>"

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], source: str = "<inline>") -> "Policy":
        if not isinstance(raw, dict):
            raise PolicyError(f"{source}: top level of a policy must be a mapping")
        default_effect = str(raw.get("default_effect", "deny")).lower()
        if default_effect not in EFFECTS:
            raise PolicyError(
                f"{source}: default_effect '{default_effect}' is not one of "
                f"{', '.join(EFFECTS)}"
            )
        raw_rules = raw.get("rules") or []
        if not isinstance(raw_rules, list):
            raise PolicyError(f"{source}: 'rules' must be a list")
        rules = [Rule.from_dict(r, i) for i, r in enumerate(raw_rules)]

        raw_aggregate_rules = raw.get("aggregate_rules") or []
        if not isinstance(raw_aggregate_rules, list):
            raise PolicyError(f"{source}: 'aggregate_rules' must be a list")
        aggregate_rules = [
            AggregateRule.from_dict(r, i) for i, r in enumerate(raw_aggregate_rules)
        ]

        # One id namespace across rules and aggregate_rules — a rule and an
        # aggregate rule sharing an id would make audit log entries and
        # `govern policy diff` ambiguous about which one fired.
        seen = set()
        for rule in rules:
            if rule.id in seen:
                raise PolicyError(f"{source}: duplicate rule id '{rule.id}'")
            seen.add(rule.id)
        for rule in aggregate_rules:
            if rule.id in seen:
                raise PolicyError(
                    f"{source}: duplicate id '{rule.id}' "
                    f"(used by both rules and aggregate_rules)"
                )
            seen.add(rule.id)

        return cls(
            rules=rules,
            aggregate_rules=aggregate_rules,
            version=int(raw.get("version", 1)),
            default_effect=default_effect,
            source=source,
        )

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Policy":
        p = Path(path)
        if not p.exists():
            raise PolicyError(f"policy file not found: {p}")
        try:
            raw = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"{p}: invalid YAML — {exc}") from exc
        return cls.from_dict(raw, source=str(p))

    @classmethod
    def bundled_default(cls) -> "Policy":
        """The starter policy shipped inside the package."""
        return cls.load(Path(__file__).parent / "policies" / "default.yaml")

    @classmethod
    def discover(cls, start: Optional[os.PathLike | str] = None) -> "Policy":
        """Find a policy the way git finds .git: env var, then walk up from cwd."""
        env_path = os.environ.get("GOVERN_POLICY")
        if env_path:
            return cls.load(env_path)
        current = Path(start or Path.cwd()).resolve()
        for directory in [current, *current.parents]:
            for name in DEFAULT_POLICY_FILENAMES:
                candidate = directory / name
                if candidate.exists():
                    return cls.load(candidate)
        return cls.bundled_default()

    def evaluate(self, action: str, resource: str, environment: str):
        """Return (effect, matched_rule). Deny beats approval beats allow."""
        matched = [r for r in self.rules if r.matches(action, resource, environment)]
        if not matched:
            return self.default_effect, None
        winner = max(matched, key=lambda r: (PRECEDENCE[r.effect], SEVERITIES.index(r.severity)))
        return winner.effect, winner
