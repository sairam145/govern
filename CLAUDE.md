# govern Development Context

## What govern does

Non-cooperative policy enforcement for AI agents. Wraps the actual client call, tool function, or subprocess — not an `audit()` hook the agent is supposed to call. Policy is data (YAML), not code. Three enforcement points: wrap SDK clients, decorate tool functions, replace subprocess.run.

Current capabilities:
- **Per-call policy matching**: glob-based rules over (action, resource, environment), precedence: deny > require_approval > allow
- **Cross-agent collusion detection**: aggregate_rules watch for thresholds crossing in time windows (distinct_agents or total_calls), can alert or deny
- **Dashboard**: read-only monitoring over audit log (activity feed, timeline, per-agent summary)
- **Policy simulate**: replay candidate policies against real history before shipping
- **Approval gates**: require_approval effect resolves synchronously through an approval handler (default: deny if no human present)

## Strategic pivot: The action-chain layer

The differentiator is not policy enforcement alone — IAM/Entra/CloudTrail/Palo Alto already solve identity/authorization/logging/runtime-monitoring separately.

govern's unique angle: **reconstruction of full action chains across humans, agents, tools, and infrastructure.**

Not just "did this action comply" but "did this action comply *given what preceded it?*" — e.g., five agents reading different data shards (collusion detection) *or* an agent modifying terraform state then immediately deleting an RDS backup (coordinated change). The chain is the missing context layer.

Phase 1 (current): Action chains within a single Governor instance, in-memory, proving the concept.
Phase 2 (deferred): Persistent chain store (SQLite), cross-process linking, CloudTrail/k8s audit integration.

## Locked technical decisions

**Non-negotiable:**
- SQLite audit backend — deferred, but the path is set. Current JSONL is ephemeral; Phase 2 persists to `.govern/chains.db` for chain reconstruction across restarts.
- Decorator + explicit reporting interception — govern doesn't monkey-patch; users call Governor explicitly or use the three interception points.
- Strict mode raises PolicyViolation — deny is a hard error in enforce mode, not a warning.
- require_approval resolves synchronously — no pending state in the codebase. Approval handler is called within evaluate(), decision.allowed is set immediately.
- Docker/kubectl-style CLI conventions — noun-verb pattern (govern policy list, govern agent inspect, etc.), not verb-noun or random flags.

**Semi-locked (proven by collusion work):**
- Per-policy, per-capability features over pluggable backends — aggregate_rules live in the policy YAML, not a separate config file; same detector class is reused in live enforcement, simulation, and dashboard.
- Sliding-window state for time-based thresholds — both collusion detection and (incoming) chain-aware rule matching need "what happened in the last 5m" — reuse the same windowing pattern.

## Working style

- **Bare minimum working version first** — in-memory ChainRegistry before SQLite, Phase 1 chains before multi-cloud integration.
- **Real tested code over prototypes** — test scenarios are integration tests proving the feature works end-to-end, not unit tests of isolated components.
- **Commit as work progresses** — each phase (chain reconstruction, chain-aware rules, dashboard visualization, etc.) is a separate commit, not one monster PR.
- **Preserve existing behavior** — new features are additive. If a policy has no chain_rules, zero behavior change. If chain_rules is empty, it's a no-op.

## Code structure

- **policy.py**: Policy as data. Rules live here (Rule, AggregateRule, ChainRule all in policy.py). All validation (no duplicate ids across rule types, parse durations, glob patterns) happens on load.
- **engine.py**: Policy enforcement. Governor.evaluate() runs one action through per-call rules, chain rules (if any), aggregate rules (if any), then approval handler. Audit log is JSONL, written by Governor._append().
- **chain.py** (Phase 1): ActionChain, ActionStep, ChainRegistry. In-memory. No database yet.
- **collusion.py**: Separate detector class for aggregate_rules. Reused in live enforcement, simulate, and dashboard. Same pattern for chain matching (separate class or method, reused in multiple contexts).
- **dashboard.py**: Read-only FastAPI app tailing the audit log. GET endpoints for events, agents, stats, cross-agent aggregations, and (Phase 2) chain visualization.
- **simulate.py**: Replays history through a candidate policy using the exact same evaluation logic as live enforcement.
- **cli.py**: Noun-verb commands. No policy logic here.

## Phase 1 scope (current work)

- ActionChain reconstruction within a Governor instance (in-memory)
- Chain-aware rule matching (if_previous conditions) in live enforcement only
- Integration into Governor.evaluate()
- 8 comprehensive test scenarios proving the concept
- **policy simulate does not evaluate chain rules** — see "Known Phase 1 limitation" below
- Dashboard visualization deferred to Phase 2

## Known Phase 1 limitations (document, do not solve now)

**Hard blockers for simulate + dashboard chain support:**
- Audit log entries do not record chain context (step_id, initiated_by) — they're written by the Decision object, which doesn't know about the chain
- `simulate` creates fresh Governor instances replaying JSONL; each gets a new in-memory ChainRegistry, so chains aren't reconstructed across the replay
- Without persistent chain storage, step IDs from one run can't be passed to the next run or linked across processes

**Result**: Chain rules only work in live enforcement (one Governor instance, in-memory chain state survives). `policy simulate` and the dashboard only see per-call and aggregate rules. This is acceptable for Phase 1 (proving the concept) but Phase 2 must solve it.

**Phase 2 will add:**
- Step IDs and `initiated_by` links recorded to audit log (in metadata or as top-level fields)
- SQLite backend for persistent chains (`.govern/chains.db`)
- `simulate` integration: when replaying, reconstruct chains from the audit log using step IDs
- Dashboard chain visualization

**Other Phase 1 limitations** (lower priority):
- Chains do not persist across process restarts (fixed by SQLite in Phase 2)
- Two Governor instances = two separate ChainRegistry instances (fixed by chain_id passing in Phase 2)
- No external integrations (CloudTrail, k8s audit) yet (Phase 2+)
