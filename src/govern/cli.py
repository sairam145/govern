"""govern command line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .engine import Governor, default_audit_path
from .policy import Policy, PolicyError, parse_duration


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"[govern] {target} already exists (use --force to overwrite)")
        return 1
    bundled = Path(__file__).parent / "policies" / "default.yaml"
    shutil.copyfile(bundled, target)

    # Create .govern directory if it doesn't exist (for audit log)
    govern_dir = Path(".govern")
    if not govern_dir.exists():
        govern_dir.mkdir(exist_ok=True)

    print(f"\n[govern] Starter policy written to {target}\n")
    print("NEXT STEPS:")
    print("=" * 50)
    print(f"1. Review the policy:")
    print(f"   cat {target}")
    print(f"\n2. Test a specific action:")
    print(f"   govern check s3:DeleteBucket prod-billing --env production")
    print(f"\n3. Try the demo (blocks on policy violations):")
    print(f"   govern demo")
    print(f"\n4. See the full architecture:")
    print(f"   govern show architecture")
    print(f"\n5. Once ready, commit it:")
    print(f"   git add {target} .govern/")
    print(f"   git commit -m 'Initialize govern policy'")
    print("=" * 50 + "\n")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy) if args.policy else Policy.discover()
    gov = Governor(
        agent_id="cli",
        environment=args.env,
        policy=policy,
        mode=args.mode,
        quiet=True,
        audit_log=args.audit_log,
    )
    decision = gov.evaluate(args.action, args.resource)
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, default=str))
    else:
        verdict = "ALLOW" if decision.allowed else "BLOCK"
        print(f"{verdict}  {decision.action} -> {decision.resource}")
        print(f"  effect:   {decision.effect}")
        print(f"  rule:     {decision.rule_id or '(none — default_effect)'}")
        print(f"  severity: {decision.severity}")
        print(f"  reason:   {decision.reason}")
        print(f"  policy:   {policy.source}")
    return 0 if decision.allowed else 2


def cmd_policy(args: argparse.Namespace) -> int:
    try:
        policy = Policy.load(args.policy) if args.policy else Policy.discover()
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1
    if args.validate:
        print(f"{policy.source}: OK — {len(policy.rules)} rules, "
              f"default_effect={policy.default_effect}")
        return 0
    print(f"source: {policy.source}")
    print(f"default_effect: {policy.default_effect}\n")
    for rule in policy.rules:
        print(f"  {rule.effect.upper():<16} {rule.id}  [{rule.severity}]")
        print(f"      actions:      {', '.join(rule.actions)}")
        print(f"      resources:    {', '.join(rule.resources)}")
        print(f"      environments: {', '.join(rule.environments)}")
        if rule.description:
            print(f"      {rule.description}")
        print()
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    path = Path(args.audit_log) if args.audit_log else default_audit_path()
    if not path.exists():
        print(f"no audit log at {path}")
        return 1
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    selected = []
    for line in lines[-args.tail:]:
        entry = json.loads(line)
        if args.blocked_only and entry.get("allowed"):
            continue
        selected.append((line, entry))

    if args.json:
        for line, _entry in selected:
            print(line)
        return 0

    if args.output == "json":
        print(json.dumps({
            "apiVersion": "govern/v1",
            "kind": "AuditLog",
            "source": str(path),
            "entries": [entry for _line, entry in selected],
        }, indent=2, default=str))
        return 0

    for _line, entry in selected:
        verdict = "ALLOW" if entry.get("allowed") else "BLOCK"
        print(f"{verdict}  {entry.get('agent_id')}  {entry.get('action')} -> "
              f"{entry.get('resource')}  [{entry.get('rule_id')}]")
    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    from .fleet import build_fleet, render_detail, render_table, to_json

    path = Path(args.audit_log) if args.audit_log else default_audit_path()
    fleet = build_fleet(path, since_hours=args.since, environment=args.env)

    if args.agent:
        rec = fleet.get(args.agent)
        if not rec:
            known = ", ".join(sorted(fleet)) or "(none)"
            print(f"no agent named '{args.agent}' in {path}")
            print(f"known agents: {known}")
            return 1
        if args.json:
            print(to_json({args.agent: rec}))
        else:
            render_detail(rec)
        return 0

    if args.json:
        print(to_json(fleet))
    else:
        render_table(fleet, path)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    return run_demo()


def cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print(
            "the dashboard needs optional dependencies: pip install govern-agent[dashboard]",
            file=sys.stderr,
        )
        return 1
    from .dashboard import create_app

    path = Path(args.audit_log) if args.audit_log else default_audit_path()
    app = create_app(audit_log=path)
    print(f"[govern] dashboard on http://127.0.0.1:{args.port}  (reading {path})")
    uvicorn.run(app, host="127.0.0.1", port=args.port)
    return 0


def _add_output_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", choices=("table", "json"), default="table",
                         help="output format (default: table)")


def _policy_rules_as_dicts(policy: Policy):
    return [
        {
            "id": r.id,
            "effect": r.effect,
            "actions": list(r.actions),
            "resources": list(r.resources),
            "environments": list(r.environments),
            "severity": r.severity,
            "description": r.description,
        }
        for r in policy.rules
    ]


def _print_policy_table(policy: Policy) -> None:
    print(f"source: {policy.source}")
    print(f"default_effect: {policy.default_effect}\n")
    for rule in policy.rules:
        print(f"  {rule.effect.upper():<16} {rule.id}  [{rule.severity}]")
        print(f"      actions:      {', '.join(rule.actions)}")
        print(f"      resources:    {', '.join(rule.resources)}")
        print(f"      environments: {', '.join(rule.environments)}")
        if rule.description:
            print(f"      {rule.description}")
        print()


def cmd_policy_list(args: argparse.Namespace) -> int:
    try:
        policy = Policy.load(args.policy) if args.policy else Policy.discover()
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        print(json.dumps({
            "apiVersion": "govern/v1",
            "kind": "PolicyList",
            "source": policy.source,
            "default_effect": policy.default_effect,
            "rules": _policy_rules_as_dicts(policy),
        }, indent=2, default=str))
        return 0

    _print_policy_table(policy)
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    try:
        policy = Policy.load(args.file)
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1
    print(f"{policy.source}: OK — {len(policy.rules)} rules, "
          f"default_effect={policy.default_effect}")
    return 0


def _diff_rules(a: Policy, b: Policy) -> dict:
    rules_a = {r.id: r for r in a.rules}
    rules_b = {r.id: r for r in b.rules}
    return {
        "added": [rules_b[rid] for rid in rules_b if rid not in rules_a],
        "removed": [rules_a[rid] for rid in rules_a if rid not in rules_b],
        "changed": [
            (rules_a[rid], rules_b[rid])
            for rid in rules_a
            if rid in rules_b and rules_a[rid] != rules_b[rid]
        ],
    }


def cmd_policy_diff(args: argparse.Namespace) -> int:
    try:
        policy_a = Policy.load(args.file_a)
        policy_b = Policy.load(args.file_b)
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1

    diff = _diff_rules(policy_a, policy_b)
    print(f"comparing {policy_a.source} -> {policy_b.source}\n")

    if policy_a.default_effect != policy_b.default_effect:
        print(f"default_effect: {policy_a.default_effect} -> {policy_b.default_effect}\n")

    if not diff["added"] and not diff["removed"] and not diff["changed"]:
        print("no rule differences")
        return 0

    if diff["added"]:
        print(f"added rules ({len(diff['added'])}):")
        for rule in diff["added"]:
            print(f"  + {rule.effect.upper():<16} {rule.id}  [{rule.severity}]")
        print()

    if diff["removed"]:
        print(f"removed rules ({len(diff['removed'])}):")
        for rule in diff["removed"]:
            print(f"  - {rule.effect.upper():<16} {rule.id}  [{rule.severity}]")
        print()

    if diff["changed"]:
        print(f"changed rules ({len(diff['changed'])}):")
        for old, new in diff["changed"]:
            print(f"  ~ {old.id}")
            for field_name in ("effect", "actions", "resources", "environments",
                               "severity", "description"):
                old_val, new_val = getattr(old, field_name), getattr(new, field_name)
                if old_val != new_val:
                    print(f"      {field_name}: {old_val} -> {new_val}")
        print()

    return 0


def cmd_policy_apply(args: argparse.Namespace) -> int:
    try:
        Policy.load(args.file)
    except PolicyError as exc:
        print(f"invalid policy, not applying: {exc}", file=sys.stderr)
        return 1

    target = Path(args.policy) if args.policy else Path("govern.yaml")
    if target.exists():
        backup = target.parent / (target.name + ".bak")
        shutil.copyfile(target, backup)
        print(f"backed up {target} -> {backup}")

    shutil.copyfile(args.file, target)
    print(f"applied {args.file} -> {target}")
    return 0


def cmd_policy_simulate(args: argparse.Namespace) -> int:
    from .simulate import render_table, simulate, to_dict

    try:
        policy = Policy.load(args.file)
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1

    audit_path = Path(args.against) if args.against else (
        Path(args.audit_log) if args.audit_log else default_audit_path()
    )
    try:
        since_hours = parse_duration(args.since) / 3600.0 if args.since else None
    except PolicyError as exc:
        print(f"invalid --since: {exc}", file=sys.stderr)
        return 1

    # Warn if policy contains chain_rules — they are not evaluated by simulate
    if policy.chain_rules:
        count = len(policy.chain_rules)
        rule_text = "rule" if count == 1 else "rules"
        print(
            f"[govern] WARNING: {count} chain_{rule_text} in this policy will NOT be evaluated.\n"
            f"[govern] Chain rules require persistent cross-process chains (Phase 2).\n"
            f"[govern] Simulate results reflect per-call and aggregate_rules only.\n"
        )

    result = simulate(policy, audit_path, since_hours=since_hours)

    if args.output == "json":
        print(json.dumps(to_dict(result), indent=2, default=str))
    else:
        render_table(result, diff_only=args.diff)

    if args.fail_on_new_blocks and result.new_denials:
        return 1
    return 0


def cmd_agent_list(args: argparse.Namespace) -> int:
    from .fleet import build_fleet, render_table, to_dicts

    path = Path(args.audit_log) if args.audit_log else default_audit_path()
    fleet = build_fleet(path, since_hours=args.since, environment=args.env)

    if args.output == "json":
        print(json.dumps({
            "apiVersion": "govern/v1",
            "kind": "AgentList",
            "agents": to_dicts(fleet),
        }, indent=2, default=str))
        return 0

    render_table(fleet, path)
    return 0


def cmd_agent_inspect(args: argparse.Namespace) -> int:
    from .fleet import build_fleet, read_entries, render_detail, to_dicts

    path = Path(args.audit_log) if args.audit_log else default_audit_path()
    fleet = build_fleet(path)
    rec = fleet.get(args.agent_id)
    if not rec:
        known = ", ".join(sorted(fleet)) or "(none)"
        print(f"no agent named '{args.agent_id}' in {path}")
        print(f"known agents: {known}")
        return 1

    history = sorted(
        (e for e in read_entries(path) if e.get("agent_id") == args.agent_id),
        key=lambda e: e.get("timestamp") or 0,
    )

    if args.output == "json":
        print(json.dumps({
            "apiVersion": "govern/v1",
            "kind": "AgentDetail",
            "agent": to_dicts({args.agent_id: rec})[0],
            "history": history,
        }, indent=2, default=str))
        return 0

    render_detail(rec)
    print(f"full event history ({len(history)} events):")
    for entry in history:
        verdict = "ALLOW" if entry.get("allowed") else "BLOCK"
        print(f"  {verdict}  {entry.get('action')} -> {entry.get('resource')}  "
              f"[{entry.get('effect')}]  {entry.get('timestamp')}")
    return 0


def _subparser_choices(parser: argparse.ArgumentParser) -> dict:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def cmd_completion(args: argparse.Namespace) -> int:
    parser = build_parser()
    top_level = _subparser_choices(parser)
    nested = {
        name: sorted(_subparser_choices(sub))
        for name, sub in top_level.items()
        if _subparser_choices(sub)
    }
    top_names = sorted(top_level)

    if args.shell == "bash":
        cases = "\n".join(
            f'    {name}) COMPREPLY=( $(compgen -W "{" ".join(verbs)}" -- "$cur") ) ;;'
            for name, verbs in nested.items()
        )
        print(f"""\
_govern_complete() {{
  local cur
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "{' '.join(top_names)}" -- "$cur") )
    return
  fi
  case "${{COMP_WORDS[1]}}" in
{cases}
    *) COMPREPLY=() ;;
  esac
}}
complete -F _govern_complete govern""")
    else:
        cases = "\n".join(
            f"    {name}) _values '{name} command' {' '.join(verbs)} ;;"
            for name, verbs in nested.items()
        )
        print(f"""\
#compdef govern
_govern() {{
  local -a top
  top=({' '.join(top_names)})
  if (( CURRENT == 2 )); then
    _describe 'command' top
    return
  fi
  case ${{words[2]}} in
{cases}
  esac
}}
_govern""")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show the current govern status and health overview."""
    try:
        policy = Policy.discover()
    except PolicyError:
        policy = None

    path = Path(args.audit_log) if args.audit_log else default_audit_path()

    from .fleet import build_fleet

    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║               GOVERN STATUS & HEALTH OVERVIEW               ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

    # Policy info
    if policy:
        print("POLICY")
        print("─" * 60)
        print(f"  Source:       {policy.source}")
        print(f"  Rules:        {len(policy.rules)} per-call rules")
        if policy.aggregate_rules:
            print(f"  Aggregate:    {len(policy.aggregate_rules)} cross-agent rules")
        if policy.chain_rules:
            print(f"  Chain-aware:  {len(policy.chain_rules)} coordinated-action rules")
        print(f"  Default:      {policy.default_effect}")
        print()
    else:
        print("POLICY")
        print("─" * 60)
        print("  ✗ No policy found")
        print("    Run 'govern init' to create one")
        print()

    # Audit log info
    print("AUDIT LOG")
    print("─" * 60)
    if path.exists():
        entries = path.read_text(encoding="utf-8").strip().splitlines()
        print(f"  Location:     {path}")
        print(f"  Total entries: {len(entries)}")

        fleet = build_fleet(path)
        if fleet:
            print(f"  Agents seen:  {len(fleet)}")

            # Summary stats
            total_actions = sum(r.total for r in fleet.values())
            total_blocked = sum(r.blocked for r in fleet.values())
            block_rate = (total_blocked / total_actions * 100) if total_actions else 0

            print(f"  Total actions: {total_actions}")
            print(f"  Blocked:      {total_blocked} ({block_rate:.1f}%)")

            # Recent blocked actions
            import json
            blocked_entries = []
            for line in reversed(entries[-100:]):  # check last 100 entries
                try:
                    entry = json.loads(line)
                    if not entry.get("allowed") and not entry.get("alert_type"):
                        blocked_entries.append(entry)
                except:
                    pass

            if blocked_entries:
                print(f"\n  Recent blocks (last 5):")
                for entry in blocked_entries[:5]:
                    rule = entry.get("rule_id", "unknown")
                    action = entry.get("action", "?")
                    agent = entry.get("agent_id", "?")
                    print(f"    • {action} by {agent} (rule: {rule})")
        else:
            print(f"  Location:     {path}")
            print(f"  Status:       empty (no activity yet)")
    else:
        print(f"  Location:     {path}")
        print(f"  Status:       not found (run 'govern demo' to generate activity)")

    print("\n" + "─" * 60)
    print("NEXT STEPS")
    print("─" * 60)
    if not policy:
        print("  1. Create a policy:     govern init")
    print("  • Review logs:          govern log")
    print("  • See agents:           govern agent list")
    print("  • Run the demo:         govern demo")
    print("  • Start dashboard:      govern dashboard")
    print("  • Test a rule:          govern check <action> <resource>")
    print("─" * 60 + "\n")

    return 0


def cmd_show_architecture(args: argparse.Namespace) -> int:
    """Display how govern's policy enforcement architecture works."""

    ascii_diagram = """\
╔════════════════════════════════════════════════════════════════════════════════╗
║                        GOVERN POLICY ENFORCEMENT ARCHITECTURE                  ║
╚════════════════════════════════════════════════════════════════════════════════╝

┌─ INTERCEPTION LAYER ─────────────────────────────────────────────────────────┐
│                                                                               │
│  Agent Code calls one of three interception points:                          │
│                                                                               │
│    1. govern.guard(boto3_client, service="s3")                               │
│       └─> wraps SDK client, intercepts method calls                          │
│                                                                               │
│    2. @govern.guarded("db:DropTable", resource=...)                          │
│       └─> decorator on tool functions agents can call                        │
│                                                                               │
│    3. govern.run("terraform apply -auto-approve")                            │
│       └─> replaces subprocess.run                                            │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─ POLICY ENGINE (Governor.evaluate) ──────────────────────────────────────────┐
│                                                                               │
│  1. PER-CALL RULES                                                            │
│     └─> Glob-match (action, resource, environment)                           │
│         Precedence: deny > require_approval > allow                          │
│                                                                               │
│  2. CHAIN-AWARE RULES (if enabled)                                           │
│     └─> Same action, different outcome based on what preceded it             │
│         E.g., "if terraform just ran, require approval for s3:Delete"        │
│         (in-memory, Phase 1 only)                                            │
│                                                                               │
│  3. AGGREGATE RULES (if enabled)                                             │
│     └─> Cross-agent thresholds: "N distinct agents touched resource X"       │
│         "M total calls to resource Y within time window"                      │
│         Effect: alert (log it) or deny (block the call)                      │
│                                                                               │
│  4. APPROVAL HANDLER (if require_approval matched)                           │
│     └─> Synchronous: call approval handler, get yes/no immediately          │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─ DECISION ───────────────────────────────────────────────────────────────────┐
│                                                                               │
│  ENFORCE MODE (default)          MONITOR MODE                                │
│  ─────────────────────           ────────────                                │
│  ALLOW  ──> action proceeds      ALLOW  ──> action proceeds                  │
│  BLOCK  ──> raise PolicyViolation BLOCK  ──> log it, but let it proceed      │
│  APPROVE──> action proceeds      APPROVE──> action proceeds                  │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─ AUDIT LOG (.govern/audit.jsonl) ────────────────────────────────────────────┐
│                                                                               │
│  Every decision recorded as JSON:                                            │
│  {                                                                            │
│    "action": "s3:DeleteBucket",                                              │
│    "resource": "prod-backup",                                                │
│    "allowed": false,                                                         │
│    "rule_id": "deny-destructive-prod",                                       │
│    "agent_id": "cost-optimizer",                                             │
│    "timestamp": 1704067200.5,                                                │
│    ...                                                                       │
│  }                                                                            │
│                                                                               │
│  Policy decisions also available to:                                         │
│  - Dashboard: live activity feed, timeline, per-agent summary               │
│  - CLI: govern log, govern agent list/inspect                               │
│  - Policy Simulate: replay history through candidate policies                │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘

KEY INSIGHT
───────────
Unlike per-call policy engines, govern uniquely catches:

  • Cross-agent coordination: 5 agents each reading different data shards
    (aggregate_rules: distinct_agents threshold)

  • Temporal coordination: terraform runs, then s3:Delete within 5 minutes
    (chain_rules: same action, different outcome based on chain context)

Policy is data (YAML). govern.yaml lives in your repo and is version-controlled.
"""

    mermaid_diagram = """\
graph TD
    A["Agent Code<br/>(calls API, tool, subprocess)"] -->|Interception| B["Wrapping Layer<br/>(guard/guarded/run)"]
    B -->|Extract action,<br/>resource, environment| C["Governor.evaluate()"]

    C -->|1| D1["Per-Call Rules<br/>(YAML-driven)"]
    C -->|2| D2["Chain-Aware Rules<br/>(if previous action in window)"]
    C -->|3| D3["Aggregate Rules<br/>(cross-agent thresholds)"]

    D1 -->|Glob-match<br/>Precedence: deny > require_approval > allow| E["Rule Matched?"]
    D2 -->|Pattern + time window| E
    D3 -->|Threshold check| E

    E -->|require_approval| F["Call Approval<br/>Handler"]
    F -->|Sync resolution| G{Mode?}
    E -->|allow/deny| G

    G -->|enforce| H1["ALLOW: proceed"]
    G -->|enforce| H2["DENY: raise<br/>PolicyViolation"]
    G -->|monitor| H3["ALLOW: proceed<br/>(logged as blocked)"]
    G -->|monitor| H4["BLOCK: proceed<br/>(logged as blocked)"]

    H1 -->|Record decision| I["Audit Log<br/>(.govern/audit.jsonl)"]
    H2 -->|Record decision| I
    H3 -->|Record decision| I
    H4 -->|Record decision| I

    I -->|Read-only tailing| J1["Dashboard"]
    I -->|Replay via| J2["policy simulate"]
    I -->|CLI access| J3["govern log"]

    style A fill:#e1f5ff
    style C fill:#fff3e0
    style D1 fill:#f3e5f5
    style D2 fill:#f3e5f5
    style D3 fill:#f3e5f5
    style G fill:#e8f5e9
    style I fill:#fce4ec
"""

    if args.format == "mermaid":
        print(mermaid_diagram)
        print("\nTo visualize: copy the above into https://mermaid.live")
    else:  # ascii (default)
        # Use sys.stdout.buffer for proper Unicode handling on Windows
        sys.stdout.buffer.write(ascii_diagram.encode('utf-8'))
        sys.stdout.buffer.flush()

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="govern",
        description="Policy enforcement between AI agents and infrastructure.",
    )
    parser.add_argument("-p", "--policy", help="path to a policy file")
    parser.add_argument("--audit-log", help="path to the audit log")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write a starter policy file")
    p_init.add_argument("path", nargs="?", default="govern.yaml")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="evaluate one action against the policy")
    p_check.add_argument("action", help="e.g. s3:DeleteBucket")
    p_check.add_argument("resource", nargs="?", default="*")
    p_check.add_argument("--env", default="production")
    p_check.add_argument("--mode", default="enforce", choices=("enforce", "monitor"))
    p_check.add_argument("--json", action="store_true")
    p_check.set_defaults(func=cmd_check)

    p_policy = sub.add_parser("policy", help="show or validate the active policy")
    p_policy.add_argument("--validate", action="store_true")
    p_policy.set_defaults(func=cmd_policy)

    # Noun-verb form, added alongside the flag above rather than replacing
    # it: `--validate` is an optional flag and `validate` below is a verb
    # token, so argparse can never confuse the two. `govern policy` and
    # `govern policy --validate` keep working exactly as they always have.
    policy_sub = p_policy.add_subparsers(dest="policy_command")

    p_policy_list = policy_sub.add_parser("list", help="show the active policy's rules")
    _add_output_flag(p_policy_list)
    p_policy_list.set_defaults(func=cmd_policy_list)

    p_policy_validate = policy_sub.add_parser(
        "validate", help="schema-check a policy file only, no side effects"
    )
    p_policy_validate.add_argument("file")
    p_policy_validate.set_defaults(func=cmd_policy_validate)

    p_policy_diff = policy_sub.add_parser(
        "diff", help="structural diff between two policy files"
    )
    p_policy_diff.add_argument("file_a")
    p_policy_diff.add_argument("file_b")
    p_policy_diff.set_defaults(func=cmd_policy_diff)

    p_policy_apply = policy_sub.add_parser(
        "apply", help="replace the active policy file (validated first)"
    )
    p_policy_apply.add_argument("file")
    p_policy_apply.set_defaults(func=cmd_policy_apply)

    p_policy_simulate = policy_sub.add_parser(
        "simulate", help="replay audit history through a candidate policy"
    )
    p_policy_simulate.add_argument("file")
    p_policy_simulate.add_argument(
        "--against", help="audit log to replay (default: the configured audit log)"
    )
    p_policy_simulate.add_argument(
        "--since", help="only replay the last window, e.g. 24h, 7d, 30m"
    )
    p_policy_simulate.add_argument(
        "--diff", action="store_true", help="show only changed events, skip the unchanged summary"
    )
    p_policy_simulate.add_argument(
        "--fail-on-new-blocks", action="store_true",
        help="exit 1 if the candidate policy introduces any new denials",
    )
    _add_output_flag(p_policy_simulate)
    p_policy_simulate.set_defaults(func=cmd_policy_simulate)

    p_log = sub.add_parser("log", help="read the audit log")
    p_log.add_argument("--tail", type=int, default=20)
    p_log.add_argument("--blocked-only", action="store_true")
    p_log.add_argument("--json", action="store_true")
    _add_output_flag(p_log)
    p_log.set_defaults(func=cmd_log)

    p_agents = sub.add_parser(
        "agents",
        help="list every agent govern has seen, with its risk profile",
    )
    p_agents.add_argument("--agent", help="show full detail for one agent")
    p_agents.add_argument("--env", help="only count activity in this environment")
    p_agents.add_argument("--since", type=float, metavar="HOURS",
                          help="only count activity in the last N hours")
    p_agents.add_argument("--json", action="store_true")
    p_agents.set_defaults(func=cmd_agents)

    p_demo = sub.add_parser("demo", help="run a scripted agent against the policy")
    p_demo.set_defaults(func=cmd_demo)

    p_dashboard = sub.add_parser(
        "dashboard",
        help="launch a local read-only monitoring dashboard (requires the 'dashboard' extra)",
    )
    p_dashboard.add_argument("--port", type=int, default=8000)
    p_dashboard.set_defaults(func=cmd_dashboard)

    # Noun-verb sibling of `agents` (plural, unchanged above). Brand new,
    # so unlike `policy` there's no legacy bare-invocation to preserve —
    # the verb is required, so `govern agent` with nothing else gives a
    # clean argparse usage error instead of guessing.
    p_agent = sub.add_parser("agent", help="agent-centric views (noun-verb form of `agents`)")
    agent_sub = p_agent.add_subparsers(dest="agent_command", required=True)

    p_agent_list = agent_sub.add_parser(
        "list", help="every distinct agent_id seen in the audit log"
    )
    p_agent_list.add_argument("--env", help="only count activity in this environment")
    p_agent_list.add_argument("--since", type=float, metavar="HOURS",
                               help="only count activity in the last N hours")
    _add_output_flag(p_agent_list)
    p_agent_list.set_defaults(func=cmd_agent_list)

    p_agent_inspect = agent_sub.add_parser("inspect", help="one agent's full event history")
    p_agent_inspect.add_argument("agent_id")
    _add_output_flag(p_agent_inspect)
    p_agent_inspect.set_defaults(func=cmd_agent_inspect)

    p_status = sub.add_parser("status", help="show governor status and health overview")
    p_status.set_defaults(func=cmd_status)

    p_show = sub.add_parser("show", help="show architecture and reference information")
    show_sub = p_show.add_subparsers(dest="show_command", required=True)

    p_show_architecture = show_sub.add_parser(
        "architecture", help="display how govern's policy enforcement works"
    )
    p_show_architecture.add_argument(
        "--format", choices=("ascii", "mermaid"), default="ascii",
        help="output format (default: ascii)"
    )
    p_show_architecture.set_defaults(func=cmd_show_architecture)

    p_completion = sub.add_parser("completion", help="print a shell completion script")
    p_completion.add_argument("shell", choices=("bash", "zsh"))
    p_completion.set_defaults(func=cmd_completion)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        # piped into head/more and the reader closed early
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())