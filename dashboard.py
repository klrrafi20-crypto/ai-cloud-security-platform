"""
DASHBOARD (v4): Threat Detection (upload OR live CloudTrail scan) +
IAM Security Audit (live AWS scan + AI explanations), in one app.
"""

import streamlit as st
import pandas as pd
import joblib
import altair as alt
import boto3
import os
import json
import time
import networkx as nx
import matplotlib.pyplot as plt
from botocore.config import Config
from sklearn.ensemble import IsolationForest
import google.generativeai as genai
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="RC Threat Det", page_icon="🛡️", layout="wide")

st.markdown(
    '<h1 style="text-align: center;">🛡️ AI Powered Cloud Security Platform '
    '<span style="font-size: 0.4em; color: gray;">(by rafi)</span></h1>',
    unsafe_allow_html=True
)

overview_tab, tab1, tab4, tab5, tab3, tab2, tab6, tab7 = st.tabs([
    "🏠 Overview", "🔍 Threat Detection", "🌐 Security Group Scan", "📡 VPC Flow Logs",
    "🪣 S3 Exposure Scan", "🔐 IAM Security Audit", "🔒 Zero Trust Engine", "📋 Incident Report"
])

# ============================================================
# OVERVIEW TAB (summary of all other modules, at a glance)
# ============================================================
with overview_tab:
    st.write("A live summary of findings across every module you've run this session. Run scans in the other tabs to populate this view.")

    bf_count = st.session_state.get("last_bruteforce_count", 0)
    anomaly_count = st.session_state.get("last_anomaly_count", 0)
    iam_high_risk = 0
    shadow_admin_count = 0
    if "iam_results" in st.session_state:
        iam_r = st.session_state["iam_results"]
        iam_high_risk = (iam_r["risk_level"] == "HIGH").sum()
        if "shadow_admin_risk" in iam_r.columns:
            shadow_admin_count = (iam_r["shadow_admin_risk"] != "No").sum()
    s3_exposed = 0
    if "s3_results" in st.session_state:
        s3_exposed = (st.session_state["s3_results"]["risk_level"] == "HIGH").sum()
    sg_open_ports = len(st.session_state["sg_results"]) if "sg_results" in st.session_state else 0
    untrusted_identities = 0
    no_mfa_count = 0
    if "zt_results" in st.session_state:
        zt_r = st.session_state["zt_results"]
        untrusted_identities = (zt_r["trust_level"] == "Untrusted").sum()
        no_mfa_count = (zt_r["mfa_enabled"] == "No").sum()

    overall_risk = min(
        (bf_count * 15) + (iam_high_risk * 20) + (shadow_admin_count * 15) +
        (s3_exposed * 15) + (sg_open_ports * 10) + (untrusted_identities * 15) + (no_mfa_count * 5),
        100
    )

    st.subheader("🎯Overall Account Risk Score")
    st.metric("⛔Risk Score", f"{overall_risk}/100")

    st.subheader("Findings at a Glance")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🚨Threat Alerts", bf_count + anomaly_count)
    col2.metric("🔑IAM Issues", int(iam_high_risk) + int(shadow_admin_count))
    col3.metric("☁️Cloud Config Risks", int(s3_exposed) + int(sg_open_ports))
    col4.metric("👤Identity Risks", int(untrusted_identities) + int(no_mfa_count))

    st.divider()
    col5, col6, col7 = st.columns(3)
    col5.metric("⚡Brute-Force Events", bf_count)
    col5.metric("📈Anomalous Events", anomaly_count)
    col6.metric("👥Over-Privileged IAM Users", int(iam_high_risk))
    col6.metric("🕵️Shadow Admin Risks", int(shadow_admin_count))
    col7.metric("🔓Exposed S3 Buckets", int(s3_exposed))
    col7.metric("🌐Open Dangerous Ports", sg_open_ports)

    st.caption("💡 Tip: run scans in each module tab, then return here for an updated summary. Go to the 📋 Incident Report tab for a full downloadable write-up.")

# ============================================================
# TAB 1: THREAT DETECTION (upload CSV OR live CloudTrail scan)
# ============================================================
with tab1:
    st.write("Upload a CSV, or pull real CloudTrail activity live from your AWS account.")

    source_choice = st.radio("Data source:", ["Upload CSV", "Live AWS CloudTrail Scan"])

    data = None

    if source_choice == "Upload CSV":
        uploaded_file = st.file_uploader("Upload a CSV", type="csv")
        if uploaded_file is not None:
            data = pd.read_csv(uploaded_file)

    else:
        auto_monitor = st.checkbox("🔁 Enable Continuous Monitoring (auto re-scan every 12 minutes)")

        if auto_monitor:
            st_autorefresh(interval=600000, key="threat_detection_autorefresh")
            st.caption("Continuous monitoring is ON — this tab will automatically re-scan every 10 minutes while open.")

        run_live_scan = st.button("🔄 Run Live CloudTrail Scan") or auto_monitor

        if run_live_scan:
            with st.spinner("Connecting to AWS and pulling recent activity (this may take a moment)..."):
                ct_config = Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2})
                cloudtrail = boto3.client("cloudtrail", config=ct_config)

                # Pull up to 20 pages of 100 = up to 2000 events
                events = []
                next_token = None
                for _ in range(20):
                    if next_token:
                        response = cloudtrail.lookup_events(MaxResults=100, NextToken=next_token)
                    else:
                        response = cloudtrail.lookup_events(MaxResults=100)
                    events.extend(response["Events"])
                    next_token = response.get("NextToken")
                    if not next_token:
                        break

                rows = []
                for e in events:
                    detail = json.loads(e.get("CloudTrailEvent", "{}"))
                    rows.append({
                        "Event time": e.get("EventTime"),
                        "User name": e.get("Username", detail.get("userIdentity", {}).get("userName")),
                        "Event source": e.get("EventSource"),
                        "Event name": e.get("EventName"),
                        "Source IP address": detail.get("sourceIPAddress"),
                        "Error code": detail.get("errorCode"),
                        "Read-only": detail.get("readOnly", False),
                    })

                data = pd.DataFrame(rows)
                st.session_state["live_cloudtrail_data"] = data
                st.session_state["live_cloudtrail_last_scan"] = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")

        if "live_cloudtrail_data" in st.session_state:
            data = st.session_state["live_cloudtrail_data"]
            st.caption(f"Last scanned: {st.session_state.get('live_cloudtrail_last_scan', 'unknown')} — {len(data)} events pulled")

    if data is not None:
        is_synthetic = "hour_of_day" in data.columns and "failed_attempts" in data.columns
        is_real_cloudtrail = "Event name" in data.columns and "Event time" in data.columns

        if is_synthetic:
            st.info("Detected: synthetic login data. Using the trained Random Forest classifier.")

            model = joblib.load("threat_model.pkl")
            features = data.drop(columns=["is_attack"], errors="ignore")

            predictions = model.predict(features)
            probabilities = model.predict_proba(features)[:, 1]

            results = data.copy()
            results["prediction"] = ["ATTACK" if p == 1 else "Normal" for p in predictions]
            results["attack_confidence"] = (probabilities * 100).round(1).astype(str) + "%"

            attack_count = (predictions == 1).sum()
            normal_count = (predictions == 0).sum()
            col1, col2 = st.columns(2)
            col1.metric("Normal Events", normal_count)
            col2.metric("Flagged as Attacks", attack_count)
            st.bar_chart(pd.Series({"Normal": normal_count, "Attack": attack_count}))

            st.subheader("Uploaded Data Preview")
            st.dataframe(data.head())

            st.subheader("Detection Results")
            st.dataframe(results)

            st.subheader("🚨 Top 5 Highest-Risk Events")
            st.dataframe(results.sort_values("attack_confidence", ascending=False).head(5))

        elif is_real_cloudtrail:
            st.info("Detected: real AWS CloudTrail logs. Using Isolation Forest anomaly detection (no labels needed).")

            data["Event time"] = pd.to_datetime(data["Event time"])
            data["hour_of_day"] = data["Event time"].dt.hour
            data["is_error"] = data["Error code"].notna().astype(int)
            data["is_readonly"] = (data["Read-only"] == True).astype(int)

            event_counts = data["Event name"].value_counts()
            data["event_rarity"] = data["Event name"].map(lambda x: 1 / event_counts[x])

            data = data.sort_values("Event time").reset_index(drop=True)
            data["recent_failed_count"] = (
                data.groupby("User name", group_keys=False)["is_error"]
                .apply(lambda x: x.rolling(window=5, min_periods=1).sum())
            )

            features = data[["hour_of_day", "is_error", "is_readonly", "event_rarity", "recent_failed_count"]]

            data["brute_force_detected"] = False
            login_events = data[data["Event name"] == "ConsoleLogin"].copy()

            if not login_events.empty:
                for user in login_events["User name"].dropna().unique():
                    user_logins = login_events[login_events["User name"] == user].sort_values("Event time")
                    times = user_logins["Event time"].tolist()
                    idxs = user_logins.index.tolist()
                    for i in range(len(times)):
                        window_count = sum(
                            1 for t in times if 0 <= (times[i] - t).total_seconds() <= 120
                        )
                        if window_count >= 3:
                            data.loc[idxs[i], "brute_force_detected"] = True

            bruteforce_events = data[data["brute_force_detected"]]
            st.session_state["last_bruteforce_count"] = len(bruteforce_events)
            st.session_state["last_bruteforce_users"] = set(bruteforce_events["User name"].dropna().unique())

            model = IsolationForest(contamination=0.05, random_state=42)
            data["anomaly"] = model.fit_predict(features)
            data["anomaly_score"] = model.decision_function(features)

            total = len(data)
            anomalies = data[data["anomaly"] == -1].sort_values("anomaly_score")
            st.session_state["last_anomaly_count"] = len(anomalies)
            st.session_state["last_total_events"] = total

            # ---- Insider Threat labeling: is this a KNOWN internal identity ----
            # misusing legitimate access, vs an unclassified/external source?
            known_users = set()
            if "iam_results" in st.session_state:
                known_users = set(st.session_state["iam_results"]["user_name"])

            anomalies = anomalies.copy()
            anomalies["threat_type"] = anomalies["User name"].apply(
                lambda u: "Insider Threat Indicator" if u in known_users else "Anomaly (Unclassified Source)"
            )

            col1, col2 = st.columns(2)
            col1.metric("Total Events", total)
            col2.metric("Flagged as Unusual", len(anomalies))

            chart_data = pd.DataFrame({
                "Category": ["Normal", "Unusual (ML)", "Brute Force"],
                "Count": [
                    total - len(anomalies) - len(bruteforce_events),
                    len(anomalies),
                    len(bruteforce_events)
                ]
            })

            bars = alt.Chart(chart_data).mark_bar().encode(
                x=alt.X("Category", sort=None),
                y="Count",
                color=alt.Color("Category", scale=alt.Scale(
                    domain=["Normal", "Unusual (ML)", "Brute Force"],
                    range=["#4CAF50", "#FFA500", "#FF0000"]
                ), legend=None)
            )
            labels = alt.Chart(chart_data).mark_text(
                align="center", baseline="bottom", dy=-5, fontSize=14, fontWeight="bold"
            ).encode(x=alt.X("Category", sort=None), y="Count", text="Count")

            st.altair_chart(bars + labels, use_container_width=True)

            st.subheader("Data Preview")
            st.dataframe(data.head())

            st.subheader("Brute Force Detection")
            if len(bruteforce_events) > 0:
                st.write(f"BRUTE FORCE ATTACK DETECTED — {len(bruteforce_events)} suspicious login events found!")
                st.dataframe(bruteforce_events[["Event time", "User name", "Event name", "Source IP address"]])
            else:
                st.write("No brute-force pattern detected.")

            st.subheader("🚨 Top 10 Most Unusual Events")
            st.dataframe(anomalies[["Event time", "User name", "Event name",
                                     "Event source", "is_error", "is_readonly", "threat_type"]].head(10))

            st.subheader("All Flagged Events")
            st.dataframe(anomalies)

        else:
            st.error("This data doesn't match either expected format.")

    else:
        st.info("👆 Choose a data source above to get started.")

# ============================================================
# TAB 2: IAM SECURITY AUDIT (live AWS scan + AI explanations)
# ============================================================
with tab2:
    st.write("Scans your real AWS account's IAM users, maps their permissions, and uses AI to explain risks — all live.")

    HIGH_RISK_POLICIES = ["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"]

    # Real, documented IAM privilege-escalation-enabling actions.
    # A user with these (even without direct admin access) may be able to
    # grant themselves admin rights indirectly -- a "shadow admin."
    ESCALATION_ACTIONS = {
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy",
        "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy",
        "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    }

    def get_user_action_set(iam_client, username, attached_policy_arns):
        """Collect every IAM Action string this user could perform, from
        both inline policies and attached managed policy documents."""
        actions = set()

        # ---- Inline policies (written directly on the user) ----
        try:
            inline_names = iam_client.list_user_policies(UserName=username)["PolicyNames"]
            for name in inline_names:
                doc = iam_client.get_user_policy(UserName=username, PolicyName=name)["PolicyDocument"]
                for stmt in doc.get("Statement", []):
                    act = stmt.get("Action", [])
                    if isinstance(act, str):
                        actions.add(act)
                    else:
                        actions.update(act)
        except Exception:
            pass

        # ---- Attached managed policy documents ----
        for arn in attached_policy_arns:
            try:
                policy_meta = iam_client.get_policy(PolicyArn=arn)["Policy"]
                version_id = policy_meta["DefaultVersionId"]
                version = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                doc = version["PolicyVersion"]["Document"]
                for stmt in doc.get("Statement", []):
                    act = stmt.get("Action", [])
                    if isinstance(act, str):
                        actions.add(act)
                    else:
                        actions.update(act)
            except Exception:
                pass

        return actions

    if st.button("🔍 Run Full IAM Security Audit"):
        with st.spinner("Connecting to AWS and scanning IAM users..."):
            my_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
            iam = boto3.client("iam", config=my_config)

            users = iam.list_users()["Users"]
            findings = []
            G = nx.Graph()

            for user in users:
                username = user["UserName"]
                G.add_node(username, node_type="user")

                attached = iam.list_attached_user_policies(UserName=username)
                policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]
                policy_arns = [p["PolicyArn"] for p in attached["AttachedPolicies"]]

                for policy in policy_names:
                    G.add_node(policy, node_type="policy")
                    G.add_edge(username, policy)

                risky_policies = [p for p in policy_names if p in HIGH_RISK_POLICIES]
                risk_level = "HIGH" if risky_policies else "Low"

                # ---- Shadow admin check: only meaningful if not ALREADY full admin ----
                shadow_admin_risk = "No"
                escalation_paths_found = []
                if not risky_policies:
                    user_actions = get_user_action_set(iam, username, policy_arns)
                    matches = user_actions.intersection(ESCALATION_ACTIONS)
                    if matches:
                        shadow_admin_risk = "YES - Potential Escalation Path"
                        escalation_paths_found = sorted(matches)

                findings.append({
                    "user_name": username,
                    "attached_policies": ", ".join(policy_names) if policy_names else "None",
                    "risky_policies_found": ", ".join(risky_policies) if risky_policies else "None",
                    "risk_level": risk_level,
                    "shadow_admin_risk": shadow_admin_risk,
                    "escalation_actions": ", ".join(escalation_paths_found) if escalation_paths_found else "None",
                })

            results = pd.DataFrame(findings)
            st.session_state["iam_results"] = results
            st.session_state["iam_graph"] = G

        st.success(f"Scan complete — found {len(results)} IAM user(s).")

    if "iam_results" in st.session_state:
        results = st.session_state["iam_results"]
        G = st.session_state["iam_graph"]

        high_risk_count = (results["risk_level"] == "HIGH").sum()
        bruteforce_count = st.session_state.get("last_bruteforce_count", 0)

        unified_score = (high_risk_count * 40) + (bruteforce_count * 15)
        unified_score = min(unified_score, 100)

        st.subheader("🎯 Unified Account Risk Score")
        col1, col2, col3 = st.columns(3)
        col1.metric("Overall Risk Score", f"{unified_score}/100")
        col2.metric("HIGH-Risk IAM Users", high_risk_count)
        col3.metric("Brute-Force Events (last scan)", bruteforce_count)

        st.subheader("IAM Audit Results")
        st.dataframe(results)

        shadow_admins = results[results["shadow_admin_risk"] != "No"]
        st.subheader("🕵️ Shadow Admin Detection")
        if len(shadow_admins) > 0:
            st.write(f"⚠️ {len(shadow_admins)} user(s) found with potential privilege escalation paths — they could grant themselves admin access even without holding it directly.")
            st.dataframe(shadow_admins[["user_name", "escalation_actions"]])
        else:
            st.write("✅ No shadow admin / privilege escalation paths detected.")

        st.subheader("IAM Relationship Graph")
        node_colors = []
        for node in G.nodes():
            node_type = G.nodes[node].get("node_type")
            if node_type == "user":
                node_colors.append("#4A90D9")
            elif node in HIGH_RISK_POLICIES:
                node_colors.append("#E74C3C")
            else:
                node_colors.append("#7DCE82")

        num_nodes = len(G.nodes())
        fig, ax = plt.subplots(figsize=(14, 10))
        pos = nx.spring_layout(G, seed=42, k=3.5 / (num_nodes ** 0.5), iterations=200)
        nx.draw(G, pos, with_labels=True, node_color=node_colors,
                node_size=1200, font_size=6.5, font_weight="bold",
                edge_color="#bbbbbb", width=0.8, ax=ax)
        st.pyplot(fig)

        st.subheader("🤖 AI-Generated Risk Explanations")
        if st.button("Generate AI Explanations"):
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                st.error("GEMINI_API_KEY not set in this terminal session.")
            else:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel("gemini-2.5-flash-lite")

                explanations = []
                with st.spinner("Asking AI to analyze each user..."):
                    for _, row in results.iterrows():
                        time.sleep(2)
                        prompt = f"""You are a cloud security analyst. Briefly explain the
security risk of this AWS IAM user in 2-3 plain-English sentences for a beginner.

User: {row['user_name']}
Attached policies: {row['attached_policies']}
Risky policies found: {row['risky_policies_found']}
Risk level: {row['risk_level']}
"""
                        response = model.generate_content(prompt)
                        explanations.append(response.text.strip())

                results["ai_explanation"] = explanations
                st.session_state["iam_results"] = results

        if "ai_explanation" in results.columns:
            for _, row in results.iterrows():
                st.markdown(f"**{row['user_name']}**")
                st.write(row["ai_explanation"])
                st.divider()
    else:
        st.info("👆 Click the button above to run a live audit of your AWS account.")

# ============================================================
# TAB 3: S3 PUBLIC BUCKET EXPOSURE SCANNER
# ============================================================
with tab3:
    st.write("Scans every S3 bucket in your AWS account for accidental public exposure — a common cause of real data breaches.")

    if st.button("🪣 Run S3 Exposure Scan"):
        with st.spinner("Connecting to AWS and checking bucket permissions..."):
            s3_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
            s3 = boto3.client("s3", config=s3_config)

            buckets = s3.list_buckets()["Buckets"]
            findings = []

            for bucket in buckets:
                name = bucket["Name"]
                result = {
                    "bucket_name": name,
                    "block_public_access": "Unknown",
                    "publicly_accessible": "No",
                    "risk_level": "Low",
                }

                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    settings = pab["PublicAccessBlockConfiguration"]
                    all_blocked = all(settings.values())
                    result["block_public_access"] = "Fully Blocked" if all_blocked else "Partially Open"
                    if not all_blocked:
                        result["publicly_accessible"] = "Possible"
                        result["risk_level"] = "HIGH"
                except Exception:
                    result["block_public_access"] = "Not Configured"
                    result["publicly_accessible"] = "Possible"
                    result["risk_level"] = "HIGH"

                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl["Grants"]:
                        uri = grant.get("Grantee", {}).get("URI", "")
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            result["publicly_accessible"] = "YES - Public Grant Found"
                            result["risk_level"] = "HIGH"
                except Exception:
                    pass

                findings.append(result)

            s3_results = pd.DataFrame(findings)
            st.session_state["s3_results"] = s3_results

        st.success(f"Scan complete — checked {len(s3_results)} bucket(s).")

    if "s3_results" in st.session_state:
        s3_results = st.session_state["s3_results"]

        exposed_count = (s3_results["risk_level"] == "HIGH").sum()

        col1, col2 = st.columns(2)
        col1.metric("Total Buckets Scanned", len(s3_results))
        col2.metric("Potentially Exposed", exposed_count)

        if exposed_count > 0:
            st.write(f"⚠️ {exposed_count} bucket(s) may be publicly accessible!")
        else:
            st.write("✅ No publicly exposed buckets found.")

        st.subheader("S3 Bucket Scan Results")
        st.dataframe(s3_results)
    else:
        st.info("👆 Click the button above to scan your S3 buckets.")

# ============================================================
# TAB 4: SECURITY GROUP SCANNER (open ports to the internet)
# ============================================================
with tab4:
    st.write("Scans your AWS Security Groups for dangerous ports left open to the entire internet (0.0.0.0/0) — a common way real servers get compromised.")

    DANGEROUS_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
    }

    if st.button("🌐 Run Security Group Scan"):
        with st.spinner("Connecting to AWS and checking Security Groups..."):
            ec2_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
            ec2 = boto3.client("ec2", config=ec2_config)

            response = ec2.describe_security_groups()
            groups = response["SecurityGroups"]

            findings = []

            for group in groups:
                group_name = group.get("GroupName", "Unnamed")
                group_id = group["GroupId"]

                for rule in group.get("IpPermissions", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")

                        if cidr == "0.0.0.0/0":
                            if from_port is None:
                                # No port restriction = ALL ports open
                                findings.append({
                                    "security_group": f"{group_name} ({group_id})",
                                    "open_port": "ALL PORTS",
                                    "service": "ALL",
                                    "open_to": cidr,
                                    "risk_level": "HIGH",
                                })
                            else:
                                for port, service in DANGEROUS_PORTS.items():
                                    if from_port <= port <= to_port:
                                        findings.append({
                                            "security_group": f"{group_name} ({group_id})",
                                            "open_port": port,
                                            "service": service,
                                            "open_to": cidr,
                                            "risk_level": "HIGH",
                                        })

            sg_results = pd.DataFrame(findings) if findings else pd.DataFrame(
                columns=["security_group", "open_port", "service", "open_to", "risk_level"]
            )
            st.session_state["sg_results"] = sg_results
            st.session_state["sg_total_groups"] = len(groups)

        st.success(f"Scan complete — checked {len(groups)} security group(s).")

    if "sg_results" in st.session_state:
        sg_results = st.session_state["sg_results"]
        total_groups = st.session_state.get("sg_total_groups", 0)

        col1, col2 = st.columns(2)
        col1.metric("Total Security Groups", total_groups)
        col2.metric("Dangerous Open Ports Found", len(sg_results))

        if len(sg_results) > 0:
            st.write(f"⚠️ {len(sg_results)} dangerous open port rule(s) found — exposed to the entire internet!")
            st.dataframe(sg_results)
        else:
            st.write("✅ No dangerous ports found open to the internet.")
    else:
        st.info("👆 Click the button above to scan your Security Groups.")

# ============================================================
# TAB 5: VPC FLOW LOG ANALYZER (network traffic monitoring)
# ============================================================
with tab5:
    st.write("Analyzes real VPC network traffic for suspicious patterns like port scanning (many rejected connection attempts from one source).")

    LOG_GROUP = "vpc-flow-logs"

    if st.button("📡 Analyze VPC Flow Logs"):
        with st.spinner("Fetching and parsing network traffic logs..."):
            logs_config = Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2})
            logs_client = boto3.client("logs", config=logs_config)

            try:
                streams = logs_client.describe_log_streams(
                    logGroupName=LOG_GROUP,
                    orderBy="LastEventTime",
                    descending=True,
                    limit=5
                )["logStreams"]
            except Exception as e:
                streams = []
                st.error(f"Could not read log group: {e}")

            all_events = []
            for stream in streams:
                events = logs_client.get_log_events(
                    logGroupName=LOG_GROUP,
                    logStreamName=stream["logStreamName"],
                    limit=200
                )["events"]
                all_events.extend(events)

            def parse_flow_log_message(message):
                parts = message.split()
                if len(parts) < 13:
                    return None
                return {
                    "src_ip": parts[3], "dst_ip": parts[4],
                    "src_port": parts[5], "dst_port": parts[6],
                    "protocol": parts[7], "action": parts[12],
                }

            parsed = [parse_flow_log_message(e["message"]) for e in all_events]
            parsed = [p for p in parsed if p is not None]

            vpc_df = pd.DataFrame(parsed) if parsed else pd.DataFrame(
                columns=["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action"]
            )
            st.session_state["vpc_results"] = vpc_df

        st.success(f"Scan complete — analyzed {len(vpc_df)} network flow entries.")

    if "vpc_results" in st.session_state:
        vpc_df = st.session_state["vpc_results"]

        if len(vpc_df) == 0:
            st.info("No flow log data available yet. VPC Flow Logs can take 10-15+ minutes to start delivering, and require active network traffic (e.g. a running EC2 instance) to generate meaningful entries.")
        else:
            rejected = vpc_df[vpc_df["action"] == "REJECT"]
            scan_suspects = rejected["src_ip"].value_counts()
            possible_scanners = scan_suspects[scan_suspects >= 5]

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Flow Entries", len(vpc_df))
            col2.metric("Rejected Connections", len(rejected))
            col3.metric("Possible Port Scanners", len(possible_scanners))

            st.subheader("Traffic Action Breakdown")
            st.bar_chart(vpc_df["action"].value_counts())

            if len(possible_scanners) > 0:
                st.write("⚠️ Source IPs with 5+ rejected connections (possible port scanning):")
                st.dataframe(possible_scanners.rename("rejected_attempts"))

            st.subheader("All Flow Log Entries")
            st.dataframe(vpc_df)
    else:
        st.info("👆 Click the button above to analyze your VPC flow logs.")

# ============================================================
# TAB 6: ZERO TRUST IDENTITY ENGINE
# ============================================================
with tab6:
    st.write("Continuously verifies identity trust using multiple real signals: permissions, MFA status, and behavioral history — core Zero Trust principles ('never trust, always verify').")

    HIGH_RISK_POLICIES_ZT = ["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"]

    auto_verify = st.checkbox("🔁 Enable Continuous Verification (auto re-check every 60 seconds)")

    if auto_verify:
        st_autorefresh(interval=60000, key="zero_trust_autorefresh")
        st.caption("Continuous verification is ON — this tab will automatically re-scan every 60 seconds while open.")

    run_scan = st.button("🔒 Run Identity Verification Now") or auto_verify

    if run_scan:
        with st.spinner("Verifying identity trust signals..."):
            zt_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
            iam_zt = boto3.client("iam", config=zt_config)

            users = iam_zt.list_users()["Users"]
            bruteforce_users = st.session_state.get("last_bruteforce_users", set())

            zt_findings = []
            for user in users:
                username = user["UserName"]

                attached = iam_zt.list_attached_user_policies(UserName=username)
                policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]
                has_risky_policy = any(p in HIGH_RISK_POLICIES_ZT for p in policy_names)

                mfa_devices = iam_zt.list_mfa_devices(UserName=username)["MFADevices"]
                has_mfa = len(mfa_devices) > 0

                involved_in_bruteforce = username in bruteforce_users

                score = 100
                reasons = []
                if has_risky_policy:
                    score -= 40
                    reasons.append("High-risk policy attached")
                if not has_mfa:
                    score -= 30
                    reasons.append("MFA not enabled")
                if involved_in_bruteforce:
                    score -= 20
                    reasons.append("Involved in brute-force event")
                score = max(score, 0)

                if score >= 70:
                    trust_level = "Trusted"
                elif score >= 40:
                    trust_level = "Caution"
                else:
                    trust_level = "Untrusted"

                zt_findings.append({
                    "user_name": username,
                    "high_risk_policy": "Yes" if has_risky_policy else "No",
                    "mfa_enabled": "Yes" if has_mfa else "No",
                    "recent_bruteforce_activity": "Yes" if involved_in_bruteforce else "No",
                    "trust_score": score,
                    "trust_level": trust_level,
                    "reasons": ", ".join(reasons) if reasons else "No issues found",
                })

            zt_results = pd.DataFrame(zt_findings)
            st.session_state["zt_results"] = zt_results
            st.session_state["zt_last_verified"] = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")

    if "zt_results" in st.session_state:
        zt_results = st.session_state["zt_results"]

        st.caption(f"Last verified: {st.session_state.get('zt_last_verified', 'never')}")

        avg_score = round(zt_results["trust_score"].mean(), 1) if len(zt_results) > 0 else 0
        untrusted_count = (zt_results["trust_level"] == "Untrusted").sum()
        no_mfa_count = (zt_results["mfa_enabled"] == "No").sum()

        col1, col2, col3 = st.columns(3)
        col1.metric("Average Trust Score", f"{avg_score}/100")
        col2.metric("Untrusted Identities", untrusted_count)
        col3.metric("Users Without MFA", no_mfa_count)

        def highlight_trust(row):
            if row["trust_level"] == "Untrusted":
                return ["background-color: #ffcccc"] * len(row)
            elif row["trust_level"] == "Caution":
                return ["background-color: #fff3cd"] * len(row)
            else:
                return ["background-color: #d4edda"] * len(row)

        st.subheader("Identity Trust Scores")
        st.dataframe(zt_results.style.apply(highlight_trust, axis=1))

        st.subheader("Trust Score Distribution")
        chart_data_zt = pd.DataFrame({
            "user_name": zt_results["user_name"],
            "trust_score": zt_results["trust_score"]
        })
        zt_chart = alt.Chart(chart_data_zt).mark_bar().encode(
            x=alt.X("user_name", sort=None),
            y="trust_score",
            color=alt.Color("trust_score", scale=alt.Scale(scheme="redyellowgreen"), legend=None)
        )
        st.altair_chart(zt_chart, use_container_width=True)
    else:
        st.info("👆 Click the button above to run identity verification.")

# ============================================================
# TAB 7: AUTO-GENERATED INCIDENT REPORT
# ============================================================
with tab7:
    st.write("Pulls together findings from every module you've run into one consolidated security report, with an AI-written executive summary.")

    if st.button("📋 Generate Incident Report"):
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("AI CLOUD SECURITY THREAT DETECTOR — INCIDENT REPORT")
        report_lines.append(f"Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 60)

        findings_summary = []

        # ---- Threat Detection ----
        report_lines.append("\n--- THREAT DETECTION ---")
        bf_count = st.session_state.get("last_bruteforce_count", None)
        anomaly_count = st.session_state.get("last_anomaly_count", None)
        total_events = st.session_state.get("last_total_events", None)
        if total_events is not None:
            report_lines.append(f"Total events analyzed in last scan: {total_events}")
            report_lines.append(f"Unusual/anomalous events flagged: {anomaly_count}")
            if anomaly_count and anomaly_count > 0:
                findings_summary.append(f"{anomaly_count} unusual/anomalous event(s) flagged by ML detection")
        if bf_count is not None:
            report_lines.append(f"Brute-force events detected in last scan: {bf_count}")
            if bf_count > 0:
                findings_summary.append(f"{bf_count} brute-force login event(s) detected")
        if total_events is None and bf_count is None:
            report_lines.append("No threat detection scan run yet in this session.")

        # ---- IAM / CIEM ----
        report_lines.append("\n--- IAM SECURITY AUDIT (CIEM) ---")
        if "iam_results" in st.session_state:
            iam_r = st.session_state["iam_results"]
            high_risk = (iam_r["risk_level"] == "HIGH").sum()
            shadow = (iam_r["shadow_admin_risk"] != "No").sum() if "shadow_admin_risk" in iam_r.columns else 0
            report_lines.append(f"Total IAM users scanned: {len(iam_r)}")
            report_lines.append(f"HIGH-risk (over-privileged) users: {high_risk}")
            report_lines.append(f"Shadow admin / privilege escalation risks: {shadow}")
            if high_risk > 0:
                findings_summary.append(f"{high_risk} over-privileged IAM user(s)")
            if shadow > 0:
                findings_summary.append(f"{shadow} shadow admin risk(s)")
        else:
            report_lines.append("No IAM audit run yet in this session.")

        # ---- S3 ----
        report_lines.append("\n--- S3 EXPOSURE SCAN ---")
        if "s3_results" in st.session_state:
            s3_r = st.session_state["s3_results"]
            exposed = (s3_r["risk_level"] == "HIGH").sum()
            report_lines.append(f"Buckets scanned: {len(s3_r)}, potentially exposed: {exposed}")
            if exposed > 0:
                findings_summary.append(f"{exposed} potentially exposed S3 bucket(s)")
        else:
            report_lines.append("No S3 scan run yet in this session.")

        # ---- Security Groups ----
        report_lines.append("\n--- SECURITY GROUP SCAN ---")
        if "sg_results" in st.session_state:
            sg_r = st.session_state["sg_results"]
            report_lines.append(f"Dangerous open port rules found: {len(sg_r)}")
            if len(sg_r) > 0:
                findings_summary.append(f"{len(sg_r)} dangerous open port(s) to the internet")
        else:
            report_lines.append("No Security Group scan run yet in this session.")

        # ---- VPC Flow Logs ----
        report_lines.append("\n--- VPC FLOW LOG ANALYSIS ---")
        if "vpc_results" in st.session_state:
            vpc_r = st.session_state["vpc_results"]
            report_lines.append(f"Flow log entries analyzed: {len(vpc_r)}")
        else:
            report_lines.append("No VPC flow log scan run yet in this session.")

        # ---- Zero Trust ----
        report_lines.append("\n--- ZERO TRUST IDENTITY ENGINE ---")
        if "zt_results" in st.session_state:
            zt_r = st.session_state["zt_results"]
            avg_trust = round(zt_r["trust_score"].mean(), 1)
            no_mfa = (zt_r["mfa_enabled"] == "No").sum()
            untrusted = (zt_r["trust_level"] == "Untrusted").sum()
            report_lines.append(f"Average identity trust score: {avg_trust}/100")
            report_lines.append(f"Untrusted identities: {untrusted}")
            report_lines.append(f"Users without MFA: {no_mfa}")
            if untrusted > 0:
                findings_summary.append(f"{untrusted} identity/identities classified as Untrusted")
            if no_mfa > 0:
                findings_summary.append(f"{no_mfa} user(s) without MFA enabled")
        else:
            report_lines.append("No Zero Trust scan run yet in this session.")

        report_lines.append("\n--- SUMMARY OF KEY FINDINGS ---")
        if findings_summary:
            for f in findings_summary:
                report_lines.append(f"- {f}")
        else:
            report_lines.append("No significant risks found across scanned modules.")

        report_text = "\n".join(report_lines)

        # ---- AI-generated executive summary ----
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key and findings_summary:
            with st.spinner("Generating AI executive summary..."):
                genai.configure(api_key=api_key)
                ai_model = genai.GenerativeModel("gemini-2.5-flash-lite")
                exec_prompt = f"""You are a cloud security analyst writing an executive
summary for a report. Based on these findings, write a short (4-6 sentence)
professional executive summary suitable for a non-technical reader:

{chr(10).join(findings_summary)}
"""
                try:
                    exec_response = ai_model.generate_content(exec_prompt)
                    exec_summary = exec_response.text.strip()
                except Exception as e:
                    exec_summary = f"(AI summary unavailable: {e})"
        elif not findings_summary:
            exec_summary = "No significant risks were identified across the scanned modules during this session."
        else:
            exec_summary = "(Set GEMINI_API_KEY to enable AI-generated executive summaries.)"

        st.session_state["incident_report_text"] = report_text
        st.session_state["incident_exec_summary"] = exec_summary

    if "incident_report_text" in st.session_state:
        st.subheader("Executive Summary (AI-Generated)")
        st.write(st.session_state["incident_exec_summary"])

        st.subheader("Full Report")
        st.text(st.session_state["incident_report_text"])

        full_report = (
            "EXECUTIVE SUMMARY\n" + "-" * 20 + "\n" +
            st.session_state["incident_exec_summary"] + "\n\n" +
            st.session_state["incident_report_text"]
        )

        st.download_button(
            label="⬇️ Download Full Report (.txt)",
            data=full_report,
            file_name=f"incident_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    else:
        st.info("👆 Run some scans in the other tabs first, then click above to generate a consolidated report. (Works with whatever tabs you've already run this session.)")