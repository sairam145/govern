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

    Also resets the process-wide CollusionDetector singleton (engine.py)
    before and after each test — it's shared across every Governor in
    the process by design (see engine._shared_collusion_detector), so
    without this, aggregate-rule window state from one test would leak
    into the next.
    """
    monkeypatch.setenv("GOVERN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    from govern import engine
    engine.reset_collusion_detector()
    yield
    engine.reset_collusion_detector()
