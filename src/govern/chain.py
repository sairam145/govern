"""Action chain reconstruction.

Tracks a sequence of actions across humans, agents, and tools, following
parent-child initiator links. Enables policy rules to check "what happened
before this" and require gates on coordinated sequences.

Phase 1: in-memory per-Governor-instance. No persistence yet.
Phase 2: SQLite backend, cross-process chain linking via chain_id.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ActionStep:
    """One action in a chain."""

    id: str
    actor: str  # "sairam" or "agent-cost-optimizer" or "terraform"
    actor_type: str  # "human" | "agent" | "tool"
    action: str  # "terraform:Apply" or "s3:DeleteBucket"
    resource: str  # "arn:aws:rds:..." or "*"
    environment: str  # "production" or "development"
    timestamp: float
    initiated_by: Optional[str] = None  # parent step id; None means root (human)


class ActionChain:
    """Immutable ordered sequence of steps in a chain."""

    def __init__(self, steps: Optional[List[ActionStep]] = None):
        self.steps: List[ActionStep] = steps or []

    def append(self, step: ActionStep) -> None:
        """Add a step to the chain."""
        self.steps.append(step)

    def get_step(self, step_id: str) -> Optional[ActionStep]:
        """Find a step by id."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def reconstruct_from(self, step: ActionStep) -> List[ActionStep]:
        """Follow initiated_by links back to root, returning the full chain.

        Returns steps in chronological order (root to leaf).
        """
        if not step:
            return []

        # collect all steps by following initiated_by backward
        path = []
        current: Optional[ActionStep] = step
        visited = set()
        while current:
            if current.id in visited:
                # cycle detection (shouldn't happen in normal use)
                break
            visited.add(current.id)
            path.append(current)
            current = self.get_step(current.initiated_by) if current.initiated_by else None

        # path is now leaf-to-root; reverse it
        path.reverse()
        return path


class ChainRegistry:
    """In-memory store of action steps and chains.

    Per-Governor-instance. Does not persist across process boundaries.
    """

    def __init__(self):
        self._steps: Dict[str, ActionStep] = {}
        self._chain = ActionChain()

    def record_step(
        self,
        actor: str,
        actor_type: str,
        action: str,
        resource: str,
        environment: str,
        initiated_by: Optional[str] = None,
    ) -> ActionStep:
        """Record a new action step and return it.

        Args:
            actor: who/what is acting (e.g., "alice", "agent-cost-optimizer")
            actor_type: "human" | "agent" | "tool"
            action: the action being taken (e.g., "s3:DeleteBucket")
            resource: what is being acted on
            environment: the environment (production, staging, etc.)
            initiated_by: id of the step that triggered this one (None if root/human)

        Returns:
            The recorded ActionStep.
        """
        step = ActionStep(
            id=uuid.uuid4().hex[:12],
            actor=actor,
            actor_type=actor_type,
            action=action,
            resource=resource,
            environment=environment,
            timestamp=time.time(),
            initiated_by=initiated_by,
        )
        self._steps[step.id] = step
        self._chain.append(step)
        return step

    def get_step(self, step_id: str) -> Optional[ActionStep]:
        """Look up a step by id."""
        return self._steps.get(step_id)

    def reconstruct_chain_from(self, step: ActionStep) -> List[ActionStep]:
        """Get the full chain of steps that led to this one.

        Returns steps in chronological order (root to leaf).
        """
        return self._chain.reconstruct_from(step)
