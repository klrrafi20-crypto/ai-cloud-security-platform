"""
STEP 2: Train a model to detect attacks, then check how good it is.

KEY IDEA: We don't tell the model any rules. We just show it examples
(features + correct answer) and let it figure out the pattern itself.
This is called "supervised learning" -- supervised because we supervise
it with correct answers during training.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# ---- Load the data we generated in step 1 ----
data = pd.read_csv("login_events_from_cloud.csv")
python step2_train_model.py
# ---- Separate "features" (the clues) from "label" (the answer) ----
# X = everything the model is ALLOWED to look at to make a guess
# y = the correct answer, which we hide from the model during prediction
X = data.drop(columns=["is_attack"])
y = data["is_attack"]

# ---- Split into training data and testing data ----
# WHY split? If we test the model on data it already memorized during
# training, we can't tell if it actually learned a pattern or just
# "cheated" by memorizing. So we hold back 20% of the data, hide the
# answers, and see if the model can still guess correctly.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
    # stratify=y keeps the same attack/normal ratio in both train and test
)

print(f"Training on {len(X_train)} events, testing on {len(X_test)} events\n")

# ---- Create and train the model ----
# RandomForestClassifier builds many simple decision trees (think:
# a flowchart of yes/no questions like "is failed_attempts > 3?") and
# combines their votes. It's a great beginner-friendly model: accurate,
# hard to mess up, and doesn't need much tuning.
model = RandomForestClassifier(n_estimators=100, random_state=42)

# .fit() is where the actual "learning" happens -- the model looks at
# X_train and y_train together and adjusts itself to find the patterns.
model.fit(X_train, y_train)

# ---- Test it on data it has never seen ----
predictions = model.predict(X_test)

# ---- Evaluate: how good was it really? ----
print("=== Classification Report ===")
print(classification_report(y_test, predictions, target_names=["Normal", "Attack"]))

print("=== Confusion Matrix ===")
cm = confusion_matrix(y_test, predictions)
print(cm)
print("""
Reading the confusion matrix:
[[True Normals correctly caught,   Normals wrongly flagged as attacks],
 [Attacks wrongly missed,          Attacks correctly caught]]
""")

# ---- Which features mattered most? ----
# This tells us WHY the model makes its decisions -- important in
# security, because you want to explain alerts, not just get a black box.
importances = pd.Series(model.feature_importances_, index=X.columns)
print("=== Which clues mattered most to the model? ===")
print(importances.sort_values(ascending=False))

# ---- Save the trained model so we can reuse it without retraining ----
import joblib
joblib.dump(model, "threat_model.pkl")
print("\nModel saved to threat_model.pkl")