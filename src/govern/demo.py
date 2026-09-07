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
    print("=" * 62)
    print("govern demo — an agent operating on production")
    print("=" * 62 + "\n")

    govern.init(agent_id="cost-optimizer-bot", environment="production")
    s3 = govern.guard(FakeS3(), service="s3")

    print("\n1. agent lists buckets to find unused storage")
    s3.list_buckets()
    print("   -> succeeded\n")

    print("2. agent writes a report (mutation, production)")
    try:
        s3.put_object(Bucket="prod-billing", Key="reports/cost.json")
        print("   -> succeeded\n")
    except PolicyViolation as exc:
        print(f"   -> stopped: {exc.decision.reason}\n")

    print("3. agent decides the bucket is unused and deletes it")
    try:
        s3.delete_bucket(Bucket="prod-billing")
        print("   -> succeeded (this should not happen)\n")
    except PolicyViolation as exc:
        print(f"   -> stopped by rule '{exc.decision.rule_id}' "
              f"[{exc.decision.severity}]\n")

    print("4. agent falls back to the shell")
    try:
        govern.run("rm -rf /var/lib/billing", capture_output=True)
        print("   -> succeeded (this should not happen)\n")
    except PolicyViolation as exc:
        print(f"   -> stopped by rule '{exc.decision.rule_id}' "
              f"[{exc.decision.severity}]\n")

    print("-" * 62)
    print("session summary")
    print("-" * 62)
    print(json.dumps(govern.summary(), indent=2))
    print(f"\naudit log: {govern.governor().audit_log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
