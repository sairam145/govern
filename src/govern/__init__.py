"""govern — a policy enforcement layer between AI agents and infrastructure.

Two ways in:

    import govern
    govern.init(agent_id="billing-bot", environment="production")

    # 1. wrap the client the agent uses (it cannot act around you)
    s3 = govern.guard(boto3.client("s3"), service="s3")
    s3.delete_bucket(Bucket="prod-billing")      # -> PolicyViolation

    # 2. or ask explicitly, when you control the call site
    if govern.audit("s3:DeleteBucket", "prod-billing"):
        ...
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .decision import Decision, PolicyViolation
from .engine import Governor, prompt_approval, deny_approval
from .policy import Policy, PolicyError, Rule
from .guard import guard, guarded, run, GuardedClient

__version__ = "0.1.0"

__all__ = [
    "init", "audit", "enforce", "session", "summary", "governor",
    "guard", "guarded", "run", "GuardedClient",
    "Governor", "Policy", "Rule", "Decision",
    "PolicyViolation", "PolicyError",
    "prompt_approval", "deny_approval",
    "__version__",
]

_GOVERNOR: Optional[Governor] = None


def _active_governor() -> Governor:
    """Lazily create a governor so guard()/run() work without explicit init."""
    global _GOVERNOR
    if _GOVERNOR is None:
        _GOVERNOR = Governor()
    return _GOVERNOR


def init(
    agent_id: str = "unnamed-agent",
    environment: str = "development",
    policy: Optional[str | Policy] = None,
    mode: str = "enforce",
    approval: Optional[Callable[[Decision], bool]] = None,
    audit_log: Optional[str] = None,
    quiet: bool = False,
) -> Governor:
    """Start a governed session and make it the process-wide default."""
    global _GOVERNOR
    resolved = Policy.load(policy) if isinstance(policy, str) else policy
    _GOVERNOR = Governor(
        agent_id=agent_id,
        environment=environment,
        policy=resolved,
        mode=mode,
        approval=approval,
        audit_log=audit_log,
        quiet=quiet,
    )
    if not quiet:
        print(f"[govern] session {_GOVERNOR.session_id} | agent={agent_id} "
              f"| env={environment} | mode={mode} | policy={_GOVERNOR.policy.source}")
    return _GOVERNOR


def governor() -> Governor:
    """The currently active Governor."""
    return _active_governor()


def audit(action: str, resource: str = "*", target: Optional[str] = None, **metadata: Any) -> Decision:
    """Evaluate an action. Returns a Decision, which is truthy if allowed."""
    return _active_governor().evaluate(action, target or resource, metadata or None)


def enforce(action: str, resource: str = "*", **metadata: Any) -> Decision:
    """Evaluate an action and raise PolicyViolation if it is not allowed."""
    return _active_governor().enforce(action, resource, metadata or None)


def summary() -> dict:
    """Session report: what was evaluated, what was blocked."""
    return _active_governor().summary()


class session:
    """Context manager form.

    >>> with govern.session("migration-bot", "production") as gov:
    ...     gov.enforce("rds:CreateSnapshot", "billing-db")
    """

    def __init__(self, agent_id: str, environment: str = "development", **kwargs: Any):
        self._kwargs = dict(agent_id=agent_id, environment=environment, **kwargs)
        self.governor: Optional[Governor] = None

    def __enter__(self) -> Governor:
        self.governor = init(**self._kwargs)
        return self.governor

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False
