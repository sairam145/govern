"""A scripted agent, used by `govern demo`.

It shows the difference that matters: the agent never calls an audit
function. It calls what it thinks is a real client. govern owns the
path to the resource.
"""

from __future__ import annotations

import json

import govern
from govern import PolicyViolation


class FakeS3:
    """Stands in for boto3.client('s3')."""

    def list_buckets(self):
        return {"Buckets": [{"Name": "prod-billing"}, {"Name": "dev-scratch"}]}

    def put_object(self, Bucket, Key, Body=b""):
        return {"ETag": "written", "Bucket": Bucket, "Key": Key}

    def delete_bucket(self, Bucket):
        return {"Deleted": Bucket}


def run_demo() -> int:
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "GOVERN POLICY ENFORCEMENT DEMO" + " " * 28 + "║")
    print("║" + " " * 78 + "║")
    print("║ Non-cooperative policy enforcement — govern wraps every client call" + " " * 9 + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "═" * 78 + "╝\n")

    # PART 1: ENFORCE MODE (default)
    print("▶ PART 1: ENFORCE MODE (default — blocks violations)")
    print("─" * 80)

    govern.init(agent_id="cost-optimizer-bot", environment="production")
    s3 = govern.guard(FakeS3(), service="s3")

    print("\n[1/4] Agent lists buckets to find candidates for deletion")
    print("      Action: s3:ListBuckets (read-only)")
    s3.list_buckets()
    print("      ✓ ALLOWED by rule 'allow-reads'\n")

    print("[2/4] Agent tries to write a cost analysis report")
    print("      Action: s3:PutObject in production")
    try:
        s3.put_object(Bucket="prod-billing", Key="reports/cost.json")
        print("      ✓ ALLOWED by rule 'allow-nonprod-writes'\n")
    except PolicyViolation as exc:
        print(f"      ✗ BLOCKED: {exc.decision.reason}\n")

    print("[3/4] Agent attempts to delete the bucket (destructive)")
    print("      Action: s3:DeleteBucket on prod-billing")
    try:
        s3.delete_bucket(Bucket="prod-billing")
        print("      ✗ UNEXPECTED: should have been blocked\n")
    except PolicyViolation as exc:
        print(f"      ✗ BLOCKED by rule '{exc.decision.rule_id}' [{exc.decision.severity}]")
        print(f"         Reason: {exc.decision.reason}\n")

    print("[4/4] Agent falls back to destructive shell command")
    print("      Action: shell:exec with 'rm -rf'")
    try:
        govern.run("rm -rf /var/lib/billing", capture_output=True)
        print("      ✗ UNEXPECTED: should have been blocked\n")
    except PolicyViolation as exc:
        print(f"      ✗ BLOCKED by rule '{exc.decision.rule_id}' [{exc.decision.severity}]")
        print(f"         Reason: {exc.decision.reason}\n")

    enforce_summary = govern.summary()

    print("ENFORCE MODE SUMMARY")
    print("─" * 80)
    print(f"Actions evaluated: {enforce_summary['actions_evaluated']}")
    print(f"Actions blocked:   {enforce_summary['actions_blocked']}")
    print(f"Blocked actions:")
    for blocked in enforce_summary['blocked']:
        print(f"  • {blocked['action']} → {blocked['resource']} (rule: {blocked['rule_id']})")

    # PART 2: MONITOR MODE (same agent, different mode)
    print("\n" + "▶ PART 2: MONITOR MODE (logs violations but lets them through)")
    print("─" * 80)
    print("\nSame agent, but now in monitor mode — nothing is actually blocked.")
    print("Violations are logged for review.\n")

    # Reset and restart with monitor mode
    govern.init(agent_id="cost-optimizer-bot", environment="production", mode="monitor")
    s3_monitor = govern.guard(FakeS3(), service="s3")

    print("[1/2] Agent deletes a production bucket")
    print("      Action: s3:DeleteBucket on prod-billing")
    s3_monitor.delete_bucket(Bucket="prod-billing")
    print("      ✓ PROCEEDED (but logged as would-be violation)\n")

    print("[2/2] Agent executes destructive shell command")
    print("      Action: shell:exec with 'rm -rf'")
    govern.run("rm -rf /var/lib/billing", capture_output=True)
    print("      ✓ PROCEEDED (but logged as would-be violation)\n")

    monitor_summary = govern.summary()

    print("MONITOR MODE SUMMARY")
    print("─" * 80)
    print(f"Actions evaluated: {monitor_summary['actions_evaluated']}")
    print(f"Would have blocked: {monitor_summary['actions_blocked']}")
    print(f"Policy violations detected:")
    for blocked in monitor_summary['blocked']:
        print(f"  • {blocked['action']} → {blocked['resource']} (rule: {blocked['rule_id']})")

    print("\n" + "=" * 80)
    print("KEY TAKEAWAY")
    print("=" * 80)
    print("✓ Non-cooperative: govern intercepts calls; the agent never calls audit()")
    print("✓ Enforce mode: dangerous calls are blocked immediately")
    print("✓ Monitor mode: violations are logged for review without blocking")
    print("✓ All decisions are recorded in the audit log for analysis")
    print(f"\nAudit log location: {govern.governor().audit_log}")
    print("\nRun 'govern log' to see the full audit trail")
    print("Run 'govern dashboard' to see the activity feed and per-agent stats")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
