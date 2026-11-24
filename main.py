
# ==========================================
# LogGuard - Advanced Login Analyzer
# ==========================================

import matplotlib.pyplot as plt
import csv
from datetime import datetime, timedelta
import os

# 1. Analysis settings
FAILURE_THRESHOLD = 3
TIME_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

CSV_FILE = os.path.join(BASE_DIR, "login_logs.csv")
REPORT_FILE = os.path.join(BASE_DIR, "logguard_report.txt")

# 2. Initialize statistics
ip_stats = {}
success_count = 0
failure_count = 0
total_logs = 0

# 3. Read CSV file
try:
    with open(CSV_FILE, "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(
            line for line in file if line.strip()
        )

        required_columns = {"Timestamp", "IP", "Status"}

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(
                "CSV must contain Timestamp, IP and Status columns."
            )

        for row in reader:
            ip = row["IP"].strip()
            status = row["Status"].strip().upper()

            try:
                timestamp = datetime.strptime(
                    row["Timestamp"].strip(),
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                print("Skipped invalid timestamp:", row["Timestamp"])
                continue

            if not ip or status not in ["SUCCESS", "FAIL"]:
                continue

            total_logs += 1

            if ip not in ip_stats:
                ip_stats[ip] = {
                    "SUCCESS": 0,
                    "FAIL": 0,
                    "FAIL_TIMES": []
                }

            if status == "SUCCESS":
                ip_stats[ip]["SUCCESS"] += 1
                success_count += 1

            else:
                ip_stats[ip]["FAIL"] += 1
                ip_stats[ip]["FAIL_TIMES"].append(timestamp)
                failure_count += 1

except FileNotFoundError:
    print("Error: CSV file not found.")
    raise SystemExit

except ValueError as error:
    print("Error:", error)
    raise SystemExit

# 4. Detect suspicious IP addresses
suspicious_ips = []
rapid_attack_ips = []

for ip, stats in ip_stats.items():

    # Detect repeated login failures
    if stats["FAIL"] >= FAILURE_THRESHOLD:
        suspicious_ips.append(ip)

    # Detect 5 or more failures within 1 minute
    fail_times = sorted(stats["FAIL_TIMES"])

    for i in range(len(fail_times)):
        count = 0

        for j in range(i, len(fail_times)):
            if fail_times[j] - fail_times[i] <= TIME_WINDOW:
                count += 1
            else:
                break

        if count >= TIME_THRESHOLD:
            rapid_attack_ips.append(ip)
            break

# 5. Generate report
report = []

report.append("========== LogGuard Report ==========")
report.append(f"Analysis time: {datetime.now()}")
report.append(f"Total logs: {total_logs}")
report.append(f"Successful logins: {success_count}")
report.append(f"Failed logins: {failure_count}")

report.append("")
report.append("========== IP Statistics ==========")

for ip, stats in ip_stats.items():
    report.append(
        f"{ip} | SUCCESS: {stats['SUCCESS']} | FAIL: {stats['FAIL']}"
    )

report.append("")
report.append("========== Repeated Failure Detection ==========")

if suspicious_ips:
    for ip in suspicious_ips:
        report.append(
            f"[WARNING] {ip} - {ip_stats[ip]['FAIL']} failed attempts"
        )
else:
    report.append("No suspicious IP addresses detected.")

report.append("")
report.append("========== Time-based Attack Detection ==========")

if rapid_attack_ips:
    for ip in rapid_attack_ips:
        report.append(
            f"[HIGH RISK] {ip} - "
            f"{TIME_THRESHOLD} or more failures within 1 minute"
        )
else:
    report.append("No rapid login attacks detected.")

# 6. Print report
for line in report:
    print(line)

# 7. Save report
with open(REPORT_FILE, "w", encoding="utf-8") as file:
    for line in report:
        file.write(line + "\n")

print("\nReport saved: logguard_report.txt")


# 8. Visualize login analysis results

# Graph 1: Failed login attempts by IP
ips = list(ip_stats.keys())
failures = [ip_stats[ip]["FAIL"] for ip in ips]

bar_colors = [
    "red" if ip in rapid_attack_ips else "steelblue"
    for ip in ips
]

plt.figure(figsize=(10, 5))
plt.bar(ips, failures, color=bar_colors)

plt.title("Failed Login Attempts by IP")
plt.xlabel("IP Address")
plt.ylabel("Number of Failed Attempts")
plt.xticks(rotation=30)
plt.tight_layout()

plt.savefig(
    os.path.join(SCREENSHOT_DIR, "failed_logins_by_ip.png")
)
plt.show()


# Graph 2: Successful vs Failed Logins
plt.figure(figsize=(6, 6))

plt.pie(
    [success_count, failure_count],
    labels=["Success", "Failure"],
    autopct="%1.1f%%",
    startangle=90
)

plt.title("Login Success vs Failure Ratio")
plt.tight_layout()

plt.savefig(
    os.path.join(SCREENSHOT_DIR, "login_result_ratio.png")
)
plt.show()

print("\nVisualization saved successfully!")

