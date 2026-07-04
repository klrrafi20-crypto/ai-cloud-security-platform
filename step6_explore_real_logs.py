import pandas as pd

data = pd.read_csv("real_aws_events.csv")
print("Shape:", data.shape)
print("\nColumns:", list(data.columns))
print("\nFirst 5 rows:")
print(data.head())
print("\nEvent name counts:")
print(data["Event name"].value_counts())