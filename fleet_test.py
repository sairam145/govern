import govern

runs = [
    ("terraform-planner", "production", "monitor",
     [("terraform:Destroy", "prod-vpc"), ("terraform:Apply", "prod-vpc"), ("s3:ListBuckets", "*")]),
    ("k8s-autoscaler", "staging", "enforce",
     [("k8s:ScaleDeployment", "checkout"), ("k8s:ListPods", "*")]),
    ("db-migrator", "production", "enforce",
     [("iam:CreateAccessKey", "svc"), ("rds:DescribeDBInstances", "*"),
      ("rds:DeleteDBInstance", "prod-billing")]),
]

for agent, env, mode, calls in runs:
    govern.init(agent_id=agent, environment=env, mode=mode, quiet=True)
    for action, resource in calls:
        govern.audit(action, resource)