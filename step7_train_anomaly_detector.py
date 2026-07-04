"""
STEP 7: Detect anomalies in REAL AWS logs -- no labels needed.

Unlike our fake data, real logs don't come with "this was an attack"
answers. So instead of teaching the model right vs wrong answers
(supervised learning), we use ANOMALY DETECTION: the model learns what
"typical" activity looks like, and flags anything that doesn't fit --
even without ever being told what an attack looks like.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest

data = pd.read_csv("real_aws_events.csv")

# ---- Feature 1: hour of day the event happened ----
data["Event time"] = pd.to_datetime(data["Event time"])
data["hour_of_day"] = data["Event time"].dt.hour

# ---- Feature 2: did this action fail? ----
# NaN means no error (success). Anything else means it errored.
data["is_error"] = data["Error code"].notna().astype(int)

# ---- Feature 3: was this a read-only action (just looking) ----
# or a read-write action (actually changing something -- more risky)?
data["is_readonly"] = (data["Read-only"] == True).astype(int)

# ---- Feature 4: how RARE is this specific action? ----
# Common actions (like ListResources) are less suspicious than
# actions that almost never happen in your account.
event_counts = data["Event name"].value_counts()
data["event_rarity"] = data["Event name"].map(lambda x: 1 / event_counts[x])
# ---- NEW FEATURE: how many failed attempts by this same user recently? ----
data = data.sort_values("Event time").reset_index(drop=True)

data["recent_failed_count"] = (
    data.groupby("User name", group_keys=False)["is_error"]
    .apply(lambda x: x.rolling(window=5, min_periods=1).sum())
)

# ---- Build our feature table ----
features = data[["hour_of_day", "is_error", "is_readonly", "event_rarity", "recent_failed_count"]]

# ---- Train the anomaly detector ----
# contamination=0.05 means "assume roughly 5% of events might be unusual"
# -- a reasonable starting guess, you can adjust this later.
model = IsolationForest(contamination=0.05, random_state=42)
data["anomaly"] = model.fit_predict(features)
# fit_predict returns -1 for anomalies, 1 for normal

data["anomaly_score"] = model.decision_function(features)
# lower score = more unusual

# ---- Show the results ----
anomalies = data[data["anomaly"] == -1].sort_values("anomaly_score")

print(f"Total events analyzed: {len(data)}")
print(f"Flagged as unusual: {len(anomalies)}\n")

print("=== Top 10 Most Unusual Events ===")
print(anomalies[["Event time", "User name", "Event name", "Event source",
                  "is_error", "is_readonly"]].head(10).to_string())