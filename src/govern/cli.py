"""govern command line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .engine import Governor, default_audit_path
from .policy import Policy, PolicyError


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)")
        return 1
    bundled = Path(__file__).parent / "policies" / "default.yaml"
    shutil.copyfile(bundled, target)
    print(f"wrote starter policy to {target}")
    print("edit it, commit it, then run:  govern check s3:DeleteBucket prod-billing --env production")
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
    for line in lines[-args.tail:]:
        entry = json.loads(line)
        if args.blocked_only and entry.get("allowed"):
            continue
        if args.json:
            print(line)
            continue
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

    p_log = sub.add_parser("log", help="read the audit log")
    p_log.add_argument("--tail", type=int, default=20)
    p_log.add_argument("--blocked-only", action="store_true")
    p_log.add_argument("--json", action="store_true")
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