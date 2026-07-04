import boto3
import pandas as pd

print("Connecting to S3...")

s3 = boto3.client("s3")

BUCKET_NAME = "rafi-cloudsecurity-2026"
FILE_NAME = "login_events.csv"

print(f"Downloading {FILE_NAME} from bucket {BUCKET_NAME}...")

s3.download_file(BUCKET_NAME, FILE_NAME, "login_events_from_cloud.csv")

print("Downloaded successfully!")

data = pd.read_csv("login_events_from_cloud.csv")
print(data.head())
print(f"\nTotal rows pulled from the CLOUD: {len(data)}")