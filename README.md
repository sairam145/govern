# govern

A policy enforcement layer that sits between AI agents and the infrastructure they act on.

## The design decision

Most agent-guardrail prototypes expose an `audit()` function the agent is supposed to call before doing something dangerous. That only works if the agent cooperates — which is exactly the assumption you cannot make. It's a logging convention, not a control.

`govern` wraps the client, the tool function, or the subprocess call instead. The agent doesn't get a choice about whether policy runs, because govern owns the only path to the resource.

Policy itself is data — a YAML file a customer can edit, review, and commit — not `if` statements in Python.

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

## Status

v0.1.0 prototype. The API is intentionally small so the core idea can move without breaking the surface.
