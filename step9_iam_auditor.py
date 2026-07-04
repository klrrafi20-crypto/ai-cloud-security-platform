"""
STEP 9: IAM Auditor - scans real AWS IAM users and flags overly broad
permissions ("over-privileged" users).
"""

import boto3
from botocore.config import Config
import pandas as pd

my_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
iam = boto3.client("iam", config=my_config)

HIGH_RISK_POLICIES = [
    "AdministratorAccess",
    "IAMFullAccess",
    "PowerUserAccess",
]

def audit_users():
    findings = []
    users = iam.list_users()["Users"]
    print(f"Found {len(users)} IAM user(s) in this account.\n")

    for user in users:
        username = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=username)
        policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]

        risky_policies = [p for p in policy_names if p in HIGH_RISK_POLICIES]
        risk_level = "HIGH" if risky_policies else "Low"

        findings.append({
            "user_name": username,
            "attached_policies": ", ".join(policy_names) if policy_names else "None",
            "risky_policies_found": ", ".join(risky_policies) if risky_policies else "None",
            "risk_level": risk_level,
        })

    return pd.DataFrame(findings)

results = audit_users()

print("=== IAM Audit Results ===")
print(results.to_string(index=False))

results.to_csv("iam_audit_results.csv", index=False)
print("\nSaved to iam_audit_results.csv")

high_risk_count = (results["risk_level"] == "HIGH").sum()
print(f"\n{high_risk_count} user(s) flagged as HIGH risk.")