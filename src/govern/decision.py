"""The object every policy evaluation returns.

A bool is not enough: callers need to know *why* something was blocked,
which rule matched, and how bad it would have been. That record is what
becomes the audit log, and eventually the dashboard.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


class PolicyViolation(Exception):
    """Raised when a denied action is attempted in enforce mode."""

    def __init__(self, decision: "Decision"):
        self.decision = decision
        super().__init__(str(decision))


@dataclass
class Decision:
    action: str
    resource: str
    effect: str  # allow | deny | require_approval
    allowed: bool
    reason: str
    rule_id: Optional[str] = None
    severity: str = "info"
    mode: str = "enforce"
    agent_id: str = "unnamed-agent"
    environment: str = "development"
    session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        rule = f" [{self.rule_id}]" if self.rule_id else ""
        return f"{verdict}{rule} {self.action} on {self.resource} — {self.reason}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
