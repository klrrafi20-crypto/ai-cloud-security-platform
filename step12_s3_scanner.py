"""
STEP 12: S3 Public Bucket Scanner.

CONCEPT: By default, S3 buckets are private. But it's easy to
accidentally misconfigure one to be public -- readable (or even
writable) by anyone on the internet, no login required. This has
caused real, major data breaches. This script checks every bucket
in your account for exactly that mistake.
"""

import boto3
from botocore.config import Config
import pandas as pd

my_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
s3 = boto3.client("s3", config=my_config)

def check_bucket_public_access(bucket_name):
    """Check a single bucket for public exposure via its access block
    settings and its bucket policy/ACL."""
    findings = {
        "bucket_name": bucket_name,
        "block_public_access": "Unknown",
        "publicly_accessible": "No",
        "risk_level": "Low",
    }

    # ---- Check the bucket's "Block Public Access" settings ----
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        settings = pab["PublicAccessBlockConfiguration"]
        all_blocked = all(settings.values())
        findings["block_public_access"] = "Fully Blocked" if all_blocked else "Partially Open"
        if not all_blocked:
            findings["publicly_accessible"] = "Possible"
            findings["risk_level"] = "HIGH"
    except s3.exceptions.ClientError:
        # No block configuration set at all = relying only on defaults, worth flagging
        findings["block_public_access"] = "Not Configured"
        findings["publicly_accessible"] = "Possible"
        findings["risk_level"] = "HIGH"

    # ---- Also check bucket ACL for public grants (belt and suspenders) ----
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                findings["publicly_accessible"] = "YES - Public Grant Found"
                findings["risk_level"] = "HIGH"
    except Exception:
        pass

    return findings

def scan_all_buckets():
    buckets = s3.list_buckets()["Buckets"]
    print(f"Found {len(buckets)} bucket(s) in this account.\n")

    results = []
    for bucket in buckets:
        name = bucket["Name"]
        results.append(check_bucket_public_access(name))

    return pd.DataFrame(results)

results = scan_all_buckets()
print("=== S3 Public Exposure Scan Results ===")
print(results.to_string(index=False))

results.to_csv("s3_exposure_results.csv", index=False)
print("\nSaved to s3_exposure_results.csv")

high_risk = (results["risk_level"] == "HIGH").sum()
print(f"\n{high_risk} bucket(s) flagged as potentially exposed.")