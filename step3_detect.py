"""
STEP 3: Use the trained model like a real threat detector.

We load the model we already trained (no need to retrain every time --
just like a real system, you train once and reuse the trained model).
Then we feed it new login events and get a prediction + confidence score.
"""

import joblib
import pandas as pd

# Load the model we saved in step 2
model = joblib.load("threat_model.pkl")

def check_event(hour_of_day, failed_attempts, is_new_country,
                 data_transferred_mb, session_duration_min):
    """Feed one login event to the model and print its verdict."""
    event = pd.DataFrame([{
        "hour_of_day": hour_of_day,
        "failed_attempts": failed_attempts,
        "is_new_country": is_new_country,
        "data_transferred_mb": data_transferred_mb,
        "session_duration_min": session_duration_min,
    }])

    prediction = model.predict(event)[0]
    # predict_proba gives us the model's confidence, not just yes/no
    probability = model.predict_proba(event)[0][1]  # probability of "attack"

    verdict = "ATTACK" if prediction == 1 else "Normal"
    print(f"{verdict}  (attack confidence: {probability:.1%})")
    print(f"   Event: hour={hour_of_day}, failed_attempts={failed_attempts}, "
          f"new_country={is_new_country}, data={data_transferred_mb}MB, "
          f"duration={session_duration_min}min\n")

print("=== Testing the detector on a few example events ===\n")

# A totally normal-looking login: 2pm, no failed attempts, known country
check_event(hour_of_day=14, failed_attempts=0, is_new_country=0,
            data_transferred_mb=45, session_duration_min=25)

# A suspicious login: 3am, 8 failed attempts, new country, huge data transfer
check_event(hour_of_day=3, failed_attempts=8, is_new_country=1,
            data_transferred_mb=350, session_duration_min=4)

# A borderline case -- a normal hour but a lot of failed attempts
check_event(hour_of_day=15, failed_attempts=5, is_new_country=0,
            data_transferred_mb=60, session_duration_min=20)

print("Try editing the numbers above and re-running this file to test your own scenarios!")