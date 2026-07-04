"""
STEP 13: VPC Flow Log Analyzer.

CONCEPT: VPC Flow Logs record network traffic metadata (who talked to
whom, on what port, ACCEPT or REJECT) without capturing actual data
content. Patterns worth flagging include:
  - Many REJECTED connections from the same source (could be port
    scanning -- someone probing for open doors)
  - Traffic on unusual/sensitive ports
"""

import boto3
from botocore.config import Config
import pandas as pd
from collections import Counter

logs_config = Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2})
logs_client = boto3.client("logs", config=logs_config)

LOG_GROUP = "vpc-flow-logs"

def fetch_flow_log_events():
    print("Fetching log streams...", flush=True)
    streams = logs_client.describe_log_streams(
        logGroupName=LOG_GROUP,
        orderBy="LastEventTime",
        descending=True,
        limit=5
    )["logStreams"]

    if not streams:
        print("No log streams found yet. Flow logs may still be initializing (wait a few more minutes).")
        return []

    all_events = []
    for stream in streams:
        stream_name = stream["logStreamName"]
        print(f"Reading stream: {stream_name}", flush=True)
        events = logs_client.get_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=stream_name,
            limit=200
        )["events"]
        all_events.extend(events)

    return all_events

def parse_flow_log_message(message):
    # Standard VPC Flow Log format (space-separated):
    # version account-id interface-id srcaddr dstaddr srcport dstport
    # protocol packets bytes start end action log-status
    parts = message.split()
    if len(parts) < 13:
        return None
    return {
        "src_ip": parts[3],
        "dst_ip": parts[4],
        "src_port": parts[5],
        "dst_port": parts[6],
        "protocol": parts[7],
        "action": parts[12],
    }

events = fetch_flow_log_events()

if events:
    parsed = [parse_flow_log_message(e["message"]) for e in events]
    parsed = [p for p in parsed if p is not None]

    df = pd.DataFrame(parsed)
    print(f"\nParsed {len(df)} flow log entries.\n")
    print(df.head(10))

    print("\n=== Action breakdown ===")
    print(df["action"].value_counts())

    print("\n=== Top source IPs with REJECTED connections (possible scanning) ===")
    rejected = df[df["action"] == "REJECT"]
    print(rejected["src_ip"].value_counts().head(10))

    df.to_csv("vpc_flow_log_sample.csv", index=False)
    print("\nSaved to vpc_flow_log_sample.csv")
else:
    print("\nNo events to analyze yet.")