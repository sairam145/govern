# govern

Non-cooperative policy enforcement for AI agents: govern wraps the actual client or tool call an agent makes, so there's no `audit()` hook for the agent to just skip.

Per-call checks only ever see one agent's one action. govern also watches for coordinated behavior across agents — the starter policy ships a commented-out example that alerts when more than 3 distinct agents read `*customer_pii*` within an hour, a pattern none of them would trip individually.

```bash
pip install govern-agent
govern init            # write a starter policy (rules + an aggregate_rules example)
govern demo            # watch a scripted agent get blocked, live
govern dashboard       # pip install "govern-agent[dashboard]" first — see it happen
```

Why it's built this way: `## Design decisions` below. Full command set: `## CLI Reference`.

## Install

```bash
pip install govern-agent
# or from source:
pip install -e .
```

## Try it

```bash
govern demo                  # scripted agent hitting a production policy
govern init                  # write govern.yaml into the current repo
govern policy                # show the active policy
govern check s3:DeleteBucket prod-billing --env production
govern log --blocked-only
```

## Use it

```python
import boto3, govern

govern.init(agent_id="cost-optimizer", environment="production")

s3 = govern.guard(boto3.client("s3"), service="s3")
s3.list_buckets()                          # allowed
s3.delete_bucket(Bucket="prod-billing")    # raises PolicyViolation
```

Three interception points:

```python
# 1. wrap a client — method calls become "<service>:<Operation>"
client = govern.guard(some_sdk_client, service="k8s")

# 2. decorate a tool the agent can call
@govern.guarded("db:DropTable", resource=lambda a, k: k["table"])
def drop_table(table): ...

# 3. replace subprocess.run
govern.run("terraform apply -auto-approve")
```

## Design decisions

Most agent-guardrail prototypes expose an `audit()` function the agent is supposed to call before doing something dangerous. That only works if the agent cooperates — which is exactly the assumption you cannot make. It's a logging convention, not a control.

`govern` wraps the client, the tool function, or the subprocess call instead. The agent doesn't get a choice about whether policy runs, because govern owns the only path to the resource.

Policy itself is data — a YAML file a customer can edit, review, and commit — not `if` statements in Python.

The cross-agent detection mentioned at the top isn't a separate bolt-on: `aggregate_rules` are validated by the same policy loader as `rules`, evaluated by the same detector in live enforcement, `policy simulate`, and the dashboard — see `### aggregate_rules` under `## Policy` below for the schema.

## Policy

```yaml
version: 1
default_effect: deny

rules:
  - id: deny-destructive-prod
    effect: deny
    severity: critical
    description: Never let an agent destroy production resources.
    actions: ["*:Delete*", "*:Destroy*", "*:Terminate*"]
    resources: ["*"]
    environments: ["production", "prod"]
```

Matching is glob-based across three fields (`actions`, `resources`, `environments`). Precedence is **deny > require_approval > allow**; anything matching no rule falls through to `default_effect`. Policy is discovered like `.git` — `GOVERN_POLICY` env var, then `govern.yaml` walking up from cwd, then the bundled default.

### aggregate_rules

Regular `rules` only ever see one call at a time. `aggregate_rules` watch a rolling window across *all* agents for a count that crosses a threshold — distinct agents touching a resource, or total calls against it — and either log it or block the call that crosses the line:

```yaml
aggregate_rules:
  - id: too-many-readers-of-customer-pii
    effect: alert   # or "deny" to block the call that crosses the threshold
    description: More than 3 distinct agents read customer_pii within an hour.
    actions: ["*:Get*", "*:List*", "*:Read*"]
    resources: ["*customer_pii*"]
    environments: ["production"]
    window: "1h"
    threshold:
      type: distinct_agents   # or "total_calls"
      max: 3
```

Same glob matching as `rules`. Empty by default (`aggregate_rules: []`) — enabling one is a deliberate choice. `effect: alert` lets the action through and writes a separate `{"alert_type": "collusion"}` line to the audit log; `effect: deny` overrides the per-call decision and records both the original and final outcome. `govern policy simulate` and the dashboard's `/api/cross-agent` both replay history through the same detector, so you can see what an aggregate rule *would* have caught before turning it on.

## Modes

- `enforce` (default) — denied actions raise `PolicyViolation`
- `monitor` — nothing is blocked, but everything that *would* have been is flagged in the audit log and session summary

Monitor mode is how you get a new customer to say yes: run it for a week, show them what their agents actually tried to do, then turn on enforce.

## Approvals

```python
govern.init("migration-bot", "production", approval=govern.prompt_approval)
```

Any rule with `effect: require_approval` calls the handler. The default handler denies, since there's usually no human attached to an agent run.

## Audit log

Every decision is appended as JSONL to `.govern/audit.jsonl` (override with `GOVERN_AUDIT_LOG`). An unwritable log never takes the agent down.

## Dashboard

```bash
pip install "govern-agent[dashboard]"
govern dashboard --port 8000
```

A local, read-only view over `.govern/audit.jsonl` — a live activity feed, a blocked-vs-allowed timeline, and a per-agent summary table. It only ever tails the log; it never writes to it. `fastapi`/`uvicorn` are an optional extra, not part of the core install.

```bash
govern --audit-log path/to/audit.jsonl dashboard --port 9000
```

## CLI Reference

Commands follow a Docker/kubectl-style noun-verb pattern. Every existing invocation below the line still works exactly as it always has — the noun-verb forms are additions, not replacements.

| Command | What it does |
|---|---|
| `govern init` | write a starter policy file |
| `govern check <action> [resource]` | evaluate one action against the policy |
| `govern log` | read the audit log |
| `govern demo` | run a scripted agent against the policy |
| `govern dashboard` | launch the read-only monitoring dashboard |
| `govern policy list` | show the active policy's rules |
| `govern policy validate <file>` | schema-check a policy file, no side effects |
| `govern policy diff <a> <b>` | structural diff between two policy files |
| `govern policy apply <file>` | replace the active policy file (validated first, backed up) |
| `govern policy simulate <file>` | replay audit history through a candidate policy |
| `govern agent list` | every agent govern has seen |
| `govern agent inspect <agent_id>` | one agent's full event history |
| `govern completion bash\|zsh` | print a shell completion script |
| *(legacy)* `govern policy` / `govern policy --validate` | unchanged — same output as always |
| *(legacy)* `govern agents [--agent name]` | unchanged — same output as always |

Read-only commands (`policy list`, `agent list`, `agent inspect`, `log`) take `-o table\|json`. `-o json` always wraps the payload in an envelope with a top-level `apiVersion: "govern/v1"`, so a future schema change won't silently break a script parsing it:

```bash
govern agent list -o json | jq '.agents[] | select(.blocked > 0)'
```

### Simulating a policy change before shipping it

`policy simulate` never touches the real audit log, the active policy, or a live approval handler — it replays recorded history through a candidate policy file using the exact same rule-precedence logic (`deny > require_approval > allow`) that live enforcement uses, so what it predicts can't drift from what enforcement would actually do.

```bash
govern init tightened.yaml            # start from the current policy
$EDITOR tightened.yaml                # add a rule, e.g. deny k8s:Scale* everywhere

govern policy simulate tightened.yaml --since 7d
#   CHANGED OUTCOMES (2)
#     ALLOW -> DENY   k8s:ScaleDeployment -> checkout   agent=k8s-autoscaler   2026-09-01 09:14:02
#         new rule: deny-k8s-scale [critical]
#   6 unchanged event(s) (same outcome as recorded)
#   new denials introduced: 1  (see --fail-on-new-blocks)

# gate a CI job on it: fails the build if the new policy would introduce a new denial
govern policy simulate tightened.yaml --since 7d --fail-on-new-blocks

# happy with it? replace the active policy (validated + backed up first)
govern policy apply tightened.yaml
```

`--against <path>` points at a different audit log than the configured one; `--since 24h|7d|30m` windows the replay; `--diff` prints only the changed events, skipping the unchanged-count summary, for piping into other tools.

## Status

v0.1.0 prototype. The API is intentionally small so the core idea can move without breaking the surface.
