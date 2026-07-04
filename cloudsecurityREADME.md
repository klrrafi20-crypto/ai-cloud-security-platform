# 🛡️ AI Powered Cloud Security Platform

An end-to-end cloud security platform combining **Machine Learning**, **AWS cloud infrastructure**, and **AI-assisted analysis** — built as a hands-on learning project, tested against a real AWS account.

> Built by [Rafi](https://github.com/klrrafi20-crypto) — 

---

## 📋 Overview

This platform mirrors how real enterprise cloud security tools (like Wiz, Prisma Cloud, or Microsoft Defender for Cloud) are structured — combining **Threat Detection**, **Identity Security (CIEM)**, **Cloud Security Posture Management (CSPM)**, **Network Monitoring**, and **Zero Trust** principles into one working application.

Every module connects to real AWS services and produces genuine, live results.

---

## 🧩 Modules

| Module | What it does |
|---|---|
| 🔍 **Threat Detection** | Detects suspicious login/API activity using a trained Random Forest classifier (supervised) and an Isolation Forest anomaly detector (unsupervised) on real AWS CloudTrail logs. Includes dedicated brute-force login detection and Insider vs. External threat labeling. |
| 🔐 **IAM Security Audit (CIEM)** | Scans real AWS IAM users and permissions. Flags over-privileged users, visualizes user-to-policy relationships as a graph, and detects **Shadow Admin** risks — privilege escalation paths even without direct admin access. |
| 🪣 **S3 Exposure Scan** | Checks every S3 bucket for accidental public exposure. |
| 🌐 **Security Group Scan** | Flags dangerous ports (SSH, RDP, databases, etc.) left open to the entire internet (`0.0.0.0/0`). |
| 📡 **VPC Flow Logs** | Analyzes real network traffic for suspicious patterns like port scanning. |
| 🔒 **Zero Trust Engine** | Calculates a per-identity Trust Score from real signals: risky permissions, MFA status, and brute-force involvement. Supports continuous auto-re-verification. |
| 📋 **Incident Report** | Consolidates findings from every module into one report with an AI-generated executive summary (Google Gemini), downloadable as a `.txt` file. |

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **Machine Learning:** scikit-learn (Random Forest, Isolation Forest)
- **Cloud:** AWS (IAM, S3, EC2, VPC, CloudTrail, CloudWatch) via `boto3`
- **Dashboard:** Streamlit + Altair + Matplotlib
- **Graph Analysis:** NetworkX
- **AI Integration:** Google Gemini API
- **Desktop App Wrapper:** pywebview

---

## 🏗️ Architecture

```
AWS (IAM / S3 / EC2 / VPC / CloudTrail)
              │
        boto3 (Python SDK)
              │
   Feature Engineering & ML Models
   (Random Forest · Isolation Forest · Rule-based checks)
              │
        Streamlit Dashboard
              │
   Gemini AI (explanations & reports)
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/klrrafi20-crypto/ai-cloud-security-platform.git
cd ai-cloud-security-platform
```

### 2. Install dependencies
```bash
pip install pandas numpy scikit-learn joblib boto3 streamlit altair networkx matplotlib google-generativeai streamlit-autorefresh pywebview
```

### 3. Set up credentials (as environment variables — never hardcode these)

You'll need:
- An AWS IAM user with **read-only** access to IAM, S3, EC2, CloudTrail, and CloudWatch Logs
- A free [Google Gemini API key](https://aistudio.google.com)

**PowerShell:**
```powershell
$env:AWS_ACCESS_KEY_ID="your-access-key-id"
$env:AWS_SECRET_ACCESS_KEY="your-secret-access-key"
$env:AWS_DEFAULT_REGION="your-region"
$env:AWS_EC2_METADATA_DISABLED="true"
$env:GEMINI_API_KEY="your-gemini-key"
```

### 4. (Optional) Generate the synthetic Threat Detection model
```bash
python step1_generate_data.py
python step2_train_model.py
```
This creates `login_events.csv` and `threat_model.pkl`, used by the synthetic-data path in the Threat Detection tab.

### 5. Run the dashboard
```bash
python -m streamlit run dashboard.py
```

**Or**, to launch it as a standalone desktop app window instead of a browser tab:
```bash
python run_app.py
```
---

## ⚠️ Honest Limitations

- The platform analyzes real AWS CloudTrail logs. The supervised Threat Detection classifier was initially trained using synthetic labeled data due to the limited availability of publicly labeled cloud attack datasets. The architecture supports retraining with real-world datasets as they become available
- The free-tier Gemini API allows a limited number of requests per day; heavy testing may temporarily exhaust this quota.
- VPC Flow Logs require active AWS resources (e.g. a running EC2 instance) to produce meaningful traffic data.
- "The platform supports manual Live Scans and automatic periodic rescans during runtime. It does not provide always-on monitoring when the application is not running.
- This is a student/portfolio project, not a production-grade security tool. Only run it against AWS accounts you own or have explicit permission to scan.

---

## 📄 License

This project is open for educational and portfolio use. Feel free to fork and build on it.

---

## 🙋 About

Built as a hands-on project to learn how AI/ML can be practically applied to cloud security — from a complete beginner to a working, multi-module platform tested against real AWS infrastructure.
