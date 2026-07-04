"""
STEP 1: Generate fake (synthetic) cloud login logs.

WHY FAKE DATA? Real companies don't hand out their security logs publicly.
So we simulate realistic ones ourselves. This is a normal thing to do when
learning -- the patterns we create mimic real attacker vs normal-user behavior.

Each "row" of our data = one login event, described by 5 numbers (features):
  1. hour_of_day        -> 0-23, what time the login happened
  2. failed_attempts     -> how many wrong passwords were tried before success
  3. is_new_country      -> 1 if this country has never been used by this user before, else 0
  4. data_transferred_mb -> how much data was downloaded/uploaded in the session
  5. session_duration_min-> how long the session lasted

Each row also has a LABEL (the answer we want the model to learn to predict):
  is_attack -> 0 = normal login, 1 = attack
"""

import numpy as np
import pandas as pd

# This makes our "random" data reproducible -- you'll get the exact same
# numbers every time you run this, which makes debugging much easier.
np.random.seed(42)

def generate_normal_logins(n):
    """Simulate NORMAL user behavior: logs in during work hours, rarely
    fails a password, rarely from a new country, normal data usage."""
    return pd.DataFrame({
        "hour_of_day": np.random.normal(loc=14, scale=3, size=n).clip(0, 23),
        "failed_attempts": np.random.poisson(lam=0.3, size=n),
        "is_new_country": np.random.choice([0, 1], size=n, p=[0.95, 0.05]),
        "data_transferred_mb": np.random.normal(loc=50, scale=20, size=n).clip(0, None),
        "session_duration_min": np.random.normal(loc=30, scale=10, size=n).clip(1, None),
        "is_attack": 0
    })

def generate_attack_logins(n):
    """Simulate ATTACK behavior: odd hours (like 2-4am), many failed
    password attempts, often a new/unusual country, unusual data transfer
    (either huge exfiltration or very brief probing session)."""
    return pd.DataFrame({
        "hour_of_day": np.random.normal(loc=3, scale=2, size=n).clip(0, 23),
        "failed_attempts": np.random.poisson(lam=6, size=n),
        "is_new_country": np.random.choice([0, 1], size=n, p=[0.2, 0.8]),
        "data_transferred_mb": np.random.normal(loc=300, scale=100, size=n).clip(0, None),
        "session_duration_min": np.random.normal(loc=5, scale=3, size=n).clip(0.5, None),
        "is_attack": 1
    })

# In real life, attacks are RARE compared to normal logins.
# We simulate that: 2000 normal logins, only 150 attacks (~7% attack rate).
normal_df = generate_normal_logins(2000)
attack_df = generate_attack_logins(150)

# Combine both into one dataset, then shuffle the rows so they're not
# grouped together (a model shouldn't be able to "cheat" by row order).
data = pd.concat([normal_df, attack_df], ignore_index=True)
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

# Save it to a CSV file so later steps can just load it -- this also mimics
# how in the real world you'd export logs to a file first.
data.to_csv("login_events.csv", index=False)

print("Dataset created! Here's a peek at the first 10 rows:\n")
print(data.head(10))
print(f"\nTotal rows: {len(data)}")
print(f"Normal logins: {(data['is_attack']==0).sum()}")
print(f"Attack logins: {(data['is_attack']==1).sum()}")