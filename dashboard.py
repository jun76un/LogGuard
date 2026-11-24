
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import timedelta
import os
import ipaddress

def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# =====================================
# 1. Page Configuration
# =====================================

st.set_page_config(
    page_title="LogGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LogGuard")
st.subheader("Login Security Monitoring Dashboard")

st.markdown("---")


# =====================================
# 2. Load CSV File
# =====================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "login_logs.csv")

FAILURE_THRESHOLD = 3
TIME_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=1)

uploaded_file = st.file_uploader(
    "📂 Upload Login Log CSV",
    type=["csv"]
)

try:
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.success("Uploaded CSV file successfully!")

   
    else:
        df = pd.read_csv(CSV_FILE)
        st.info("Using the default login_logs.csv file.")

    required_columns = {"Timestamp", "IP", "Status"}

    if not required_columns.issubset(df.columns):
        st.error("CSV must contain Timestamp, IP and Status columns.")
        st.stop()

except FileNotFoundError:
    st.error("login_logs.csv file not found.")
    st.stop()

except Exception as e:
    st.error(f"Failed to load CSV file: {e}")
    st.stop()

# =====================================
# 3. Data Cleaning
# =====================================

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"],
    errors="coerce"
)

df["IP"] = df["IP"].astype(str).str.strip()
df["Status"] = df["Status"].astype(str).str.strip().str.upper()
df = df[df["IP"].apply(is_valid_ip)]

df = df.dropna(subset=["Timestamp"])
df = df[
    (df["IP"] != "") &
    (df["Status"].isin(["SUCCESS", "FAIL"]))
]

if df.empty:
    st.warning("No valid login records found.")
    st.stop()

total_logs = len(df)
success_count = (df["Status"] == "SUCCESS").sum()
failure_count = (df["Status"] == "FAIL").sum()

# =====================================
# 4. IP Statistics
# =====================================

ip_stats = df.groupby("IP")["Status"].value_counts().unstack(fill_value=0)

for status in ["SUCCESS", "FAIL"]:
    if status not in ip_stats.columns:
        ip_stats[status] = 0

ip_stats = ip_stats[["SUCCESS", "FAIL"]]

suspicious_ips = ip_stats[
    ip_stats["FAIL"] >= FAILURE_THRESHOLD
].index.tolist()


# =====================================
# 5. Time-based Attack Detection
# =====================================

rapid_attack_ips = []

failed_df = df[df["Status"] == "FAIL"].copy()

for ip, group in failed_df.groupby("IP"):
    times = sorted(group["Timestamp"].tolist())

    left = 0

    for right in range(len(times)):

        while times[right] - times[left] > TIME_WINDOW:
            left += 1

        count = right - left + 1

        if count >= TIME_THRESHOLD:
            rapid_attack_ips.append(ip)
            break

high_risk_count = len(rapid_attack_ips)

medium_risk_count = len([
    ip for ip in suspicious_ips
    if ip not in rapid_attack_ips
])

low_risk_count = len(ip_stats) - high_risk_count - medium_risk_count

# =====================================
# 6. Dashboard Metrics
# =====================================

st.header("📊 Login Statistics")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Login Attempts", total_logs)
col2.metric("Successful Logins", success_count)
col3.metric("Failed Logins", failure_count)
col4.metric("Suspicious IPs", len(suspicious_ips))

st.subheader("🛡️ Security Risk Distribution")

risk_col1, risk_col2, risk_col3 = st.columns(3)

risk_col1.markdown(
    f"<h2 style='color:red'>{high_risk_count}</h2>",
    unsafe_allow_html=True
)

risk_col1.caption("🔴 HIGH RISK")

risk_col2.markdown(
    f"<h2 style='color:orange'>{medium_risk_count}</h2>",
    unsafe_allow_html=True
)

risk_col2.caption("🟠 MEDIUM RISK")

risk_col3.markdown(
    f"<h2 style='color:green'>{low_risk_count}</h2>",
    unsafe_allow_html=True
)

risk_col3.caption("🟢 LOW RISK")

st.markdown("---")

# =====================================
# 7. Security Overview
# =====================================

st.header("🚨 Security Overview")

if rapid_attack_ips:
    st.error(
        "HIGH RISK: Rapid login attack detected!"
    )
    for ip in rapid_attack_ips:
        st.write(f"🔴 {ip} - 5 or more failures within 1 minute")

if suspicious_ips:
    st.warning(
        "MEDIUM RISK: Repeated login failures detected."
    )
    for ip in suspicious_ips:
        if ip not in rapid_attack_ips:
            st.write(f"🟠 {ip} - 3 or more failed login attempts")

if not suspicious_ips:
    st.success("No suspicious login activity detected.")


# =====================================
# 8. IP Statistics Table
# =====================================

st.header("🔍 IP Address Analysis")

display_stats = ip_stats.copy()

display_stats["Risk Level"] = display_stats.index.map(
    lambda ip:
        "HIGH" if ip in rapid_attack_ips
        else "MEDIUM" if ip in suspicious_ips
        else "LOW"
)

st.dataframe(display_stats, width="stretch")


# =====================================
# 9. IP Detail Analysis
# =====================================

st.header("🔎 IP Detail Analysis")

selected_ip = st.selectbox(
    "Select an IP Address",
    options=sorted(df["IP"].unique())
)

selected_logs = df[df["IP"] == selected_ip].copy()

st.subheader(f"Login History: {selected_ip}")

col1, col2, col3 = st.columns(3)

col1.metric("Total Attempts", len(selected_logs))
col2.metric("Successful Logins", (selected_logs["Status"] == "SUCCESS").sum())
col3.metric("Failed Logins", (selected_logs["Status"] == "FAIL").sum())

st.markdown("### Detailed Login Records")

st.dataframe(
    selected_logs.sort_values("Timestamp", ascending=False),
    width="stretch"
)

if selected_ip in rapid_attack_ips:
    st.error("HIGH RISK: Rapid login attack detected!")

elif selected_ip in suspicious_ips:
    st.warning("MEDIUM RISK: Repeated login failures detected.")

else:
    st.success("LOW RISK: No suspicious login activity detected.")


# =====================================
# 10. Visualization
# =====================================

st.header("📈 Login Analysis Graphs")

col1, col2 = st.columns(2)



with col1:
    st.subheader("Failed Logins by IP")

    chart_data = ip_stats["FAIL"].reset_index()
    chart_data.columns = ["IP", "FAIL"]

    chart_data["RISK"] = chart_data["IP"].apply(
        lambda ip: "HIGH" if ip in rapid_attack_ips
        else "MEDIUM" if ip in suspicious_ips
        else "LOW"
    )

    chart_data = chart_data.sort_values("IP")
    ip_order = chart_data["IP"].tolist()

    fig = px.bar(
        chart_data,
        x="IP",
        y="FAIL",
        color="RISK",
        category_orders={"IP": ip_order},
        color_discrete_map={
            "HIGH": "red",
            "MEDIUM": "orange",
            "LOW": "steelblue"
        }
    )

    st.plotly_chart(fig, width="stretch")


with col2:
    st.subheader("Login Success vs Failure")

    ratio_data = pd.DataFrame({
        "Count": [success_count, failure_count]
    }, index=["SUCCESS", "FAIL"])

    fig = px.pie(
        ratio_data.reset_index(),
        names="index",
        values="Count",
        hole=0.5,
        color="index",
        color_discrete_map={
            "SUCCESS": "green",
            "FAIL": "red"
        }
    )

    st.plotly_chart(fig, width="stretch")

# =====================================
# 11. IP Risk Distribution
# =====================================

st.subheader("🛡️ IP Risk Distribution")

risk_data = pd.DataFrame({
    "Risk Level": ["HIGH", "MEDIUM", "LOW"],
    "IP Count": [
        high_risk_count,
        medium_risk_count,
        low_risk_count
    ]
})

fig = px.pie(
    risk_data,
    names="Risk Level",
    values="IP Count",
    hole=0.5,
    color="Risk Level",
    color_discrete_map={
        "HIGH": "red",
        "MEDIUM": "orange",
        "LOW": "steelblue"
    }
)

st.plotly_chart(fig, width="stretch")

# =====================================
# 12. Report Download
# =====================================

st.header("📥 Download Analysis Report")

report_lines = [
    "========== LogGuard Security Report ==========",
    f"Total Login Attempts: {total_logs}",
    f"Successful Logins: {success_count}",
    f"Failed Logins: {failure_count}",
    f"Suspicious IP Count: {len(suspicious_ips)}",
    "",
    "========== Risk Distribution ==========",
    f"HIGH RISK IP Count: {high_risk_count}",
    f"MEDIUM RISK IP Count: {medium_risk_count}",
    f"LOW RISK IP Count: {low_risk_count}",
    "",
    "========== IP Analysis =========="
]

for ip, row in ip_stats.iterrows():
    if ip in rapid_attack_ips:
        risk = "HIGH"
    elif ip in suspicious_ips:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    report_lines.append(
        f"{ip} | SUCCESS: {row['SUCCESS']} | FAIL: {row['FAIL']} | RISK: {risk}"
    )

report_lines.append("")
report_lines.append("========== Security Alerts ==========")


if rapid_attack_ips or suspicious_ips:
    for ip in rapid_attack_ips:
        report_lines.append(
            f"HIGH RISK: {ip} - 5 or more failures within 1 minute"
        )

    for ip in suspicious_ips:
        if ip not in rapid_attack_ips:
            report_lines.append(
                f"MEDIUM RISK: {ip} - Repeated login failures"
            )
else:
    report_lines.append("No suspicious login activity detected.")


report_text = "\n".join(report_lines)

st.download_button(
    label="📄 Download TXT Report",
    data=report_text,
    file_name="logguard_report.txt",
    mime="text/plain"
)

# CSV Report Download

csv_report = ip_stats.copy()

csv_report["RISK"] = [
    "HIGH" if ip in rapid_attack_ips
    else "MEDIUM" if ip in suspicious_ips
    else "LOW"
    for ip in csv_report.index
]

csv_report = csv_report.reset_index()

csv_report = csv_report.rename(columns={"IP": "IP Address"})

st.download_button(
    label="📊 Download CSV Report",
    data=csv_report.to_csv(index=False).encode("utf-8-sig"),
    file_name="logguard_report.csv",
    mime="text/csv"
)

# =====================================
# CSV Summary Report Download
# =====================================

summary_data = pd.DataFrame({
    "Category": [
        "Total Login Attempts",
        "Successful Logins",
        "Failed Logins",
        "Suspicious IPs",
        "HIGH RISK IPs",
        "MEDIUM RISK IPs",
        "LOW RISK IPs"
    ],
    "Count": [
        total_logs,
        success_count,
        failure_count,
        len(suspicious_ips),
        high_risk_count,
        medium_risk_count,
        low_risk_count
    ]
})

st.download_button(
    label="📊 Download Summary CSV",
    data=summary_data.to_csv(index=False).encode("utf-8-sig"),
    file_name="logguard_summary.csv",
    mime="text/csv"
)

# =====================================
# 13. Footer
# =====================================

st.markdown("---")
st.caption("LogGuard | Login Log Analysis System")
