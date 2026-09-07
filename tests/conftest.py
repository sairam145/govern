import pytest


@pytest.fixture(autouse=True)
def isolate_audit_log(tmp_path, monkeypatch):
    """Give every test its own throwaway audit log.

    Governor() falls back to GOVERN_AUDIT_LOG, then cwd/.govern/audit.jsonl,
    when no audit_log is passed explicitly. Several tests in test_policy.py
    rely on that fallback and were silently appending fixture data (e.g.
    agent_id "t" from test_prod_write_requires_approval, with one Governor
    hardcoded to grant approval and another to refuse it) into the real
    project audit log — the same file the dashboard reads — every time the
    suite ran.
    """
    monkeypatch.setenv("GOVERN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
