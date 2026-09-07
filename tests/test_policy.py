import pytest

from govern import Governor, Policy, PolicyViolation, guard
from govern.policy import PolicyError


@pytest.fixture
def policy():
    return Policy.bundled_default()


def test_reads_allowed_in_prod(policy):
    gov = Governor("t", "production", policy=policy, quiet=True)
    assert gov.evaluate("s3:ListBuckets", "prod-billing").allowed


def test_destructive_prod_denied(policy):
    gov = Governor("t", "production", policy=policy, quiet=True)
    d = gov.evaluate("s3:DeleteBucket", "prod-billing")
    assert not d.allowed
    assert d.rule_id == "deny-destructive-prod"
    assert d.severity == "critical"


def test_deny_beats_allow_in_nonprod(policy):
    """A dev-env blanket allow must not override an environment-agnostic deny."""
    gov = Governor("t", "development", policy=policy, quiet=True)
    assert not gov.evaluate("iam:CreateAccessKey", "svc-agent").allowed


def test_prod_write_requires_approval(policy):
    granted = Governor("t", "production", policy=policy, quiet=True,
                       approval=lambda d: True)
    refused = Governor("t", "production", policy=policy, quiet=True,
                       approval=lambda d: False)
    assert granted.evaluate("s3:PutObject", "prod-billing").allowed
    assert not refused.evaluate("s3:PutObject", "prod-billing").allowed


def test_monitor_mode_allows_but_flags(policy):
    gov = Governor("t", "production", policy=policy, mode="monitor", quiet=True)
    d = gov.evaluate("s3:DeleteBucket", "prod-billing")
    assert d.allowed
    assert d.metadata["would_have_blocked"]
    assert gov.summary()["actions_blocked"] == 1


def test_shell_footgun_denied(policy):
    gov = Governor("t", "development", policy=policy, quiet=True)
    assert not gov.evaluate("shell:exec", "rm -rf /var/lib/data").allowed


def test_guarded_client_blocks_without_cooperation(policy):
    class Client:
        def delete_bucket(self, Bucket):
            raise AssertionError("the real call must never be reached")

    gov = Governor("t", "production", policy=policy, quiet=True)
    client = guard(Client(), service="s3", governor=gov)
    with pytest.raises(PolicyViolation):
        client.delete_bucket(Bucket="prod-billing")


def test_default_effect_applies_when_nothing_matches():
    p = Policy.from_dict({"version": 1, "default_effect": "deny", "rules": []})
    gov = Governor("t", "production", policy=p, quiet=True)
    d = gov.evaluate("weird:Operation", "thing")
    assert not d.allowed
    assert d.rule_id is None


def test_bad_effect_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [{"id": "x", "effect": "maybe"}]})


def test_duplicate_rule_ids_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [
            {"id": "x", "effect": "allow"},
            {"id": "x", "effect": "deny"},
        ]})
