"""
STEP 11: Use a free LLM (Google Gemini) to turn our IAM audit findings
into plain-English risk explanations and suggestions.

CONCEPT: Our earlier script (step9) already found the FACTS - which
users have which policies, and which are risky. An LLM is good at a
different job: turning structured facts into a clear, human-readable
explanation, the way a security analyst would summarize a finding in
a report.
"""

import os
import pandas as pd
import google.generativeai as genai

# ---- Load the API key from the environment variable we set ----
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY not found. Did you set it in this terminal?")

genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-2.5-flash")

# ---- Load our real IAM audit results from step 9 ----
results = pd.read_csv("iam_audit_results.csv")

print("Generating AI explanations for each IAM user...\n")

explanations = []

for _, row in results.iterrows():
    prompt = f"""You are a cloud security analyst. Briefly explain the security
risk level of this AWS IAM user in 2-3 plain-English sentences, suitable
for a beginner. If risk is Low, briefly say why it's fine. If HIGH,
explain why and suggest a fix.

User: {row['user_name']}
Attached policies: {row['attached_policies']}
Risky policies found: {row['risky_policies_found']}
Risk level: {row['risk_level']}
"""

    response = model.generate_content(prompt)
    explanation = response.text.strip()
    explanations.append(explanation)

    print(f"--- {row['user_name']} ---")
    print(explanation)
    print()

results["ai_explanation"] = explanations
results.to_csv("iam_audit_with_ai_explanations.csv", index=False)
print("Saved to iam_audit_with_ai_explanations.csv")