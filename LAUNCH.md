I built govern to catch coordinated action sequences in AI agents — where the same action gets a different policy outcome purely based on what happened before it in the chain. This is what per-call policy engines structurally cannot see.

Example: agent calls `terraform:Apply` (modifies state), then 90 seconds later calls `s3:DeleteBucket` (cleanup). Both actions individually pass per-call rules. But a chain-aware rule can say "if terraform was just run, any S3 deletion requires approval." Same agent, same s3:DeleteBucket action, but the context changes the outcome. No per-call policy tool — including Microsoft's authorization engine and others I looked at — can express this rule, because they evaluate each action in isolation.

This covers two gaps current tools miss: cross-agent coordination (five agents reading different data shards that reassemble into full access — aggregate_rules) and temporal coordination (actions that are individually safe but dangerous when combined — chain_rules). IAM/Entra/CloudTrail/Palo Alto handle identity, logging, and runtime monitoring. govern is the missing policy layer: what should this *sequence* be allowed to do, regardless of identity?

**What's proven and shipping:** Non-cooperative interception (wraps SDK clients, decorates tool functions, replaces subprocess), per-call policy rules with deny/require_approval/allow, cross-agent threshold detection (aggregate_rules), and chain-aware rule matching in live enforcement (verified by hand: same action, different outcome based on chain context, tested as working). 45 passing tests, zero regressions.

**What's not in Phase 1:** Chain rule evaluation in `policy simulate` and the dashboard (chains are in-memory per-Governor-instance; persistence deferred to Phase 2). Explicitly documented, with runtime warnings when you try to simulate a policy with chain_rules.

This is a solo project, alpha software. I'm posting this for feedback and criticism, not funding or users — I want to know if this angle on coordination is actually useful, or if others have solved it better already.

Repo: https://github.com/sairam145/govern
Try it: `govern init && govern demo`
