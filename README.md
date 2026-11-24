# 🛡️ LogGuard
### Login Security Monitoring & Analysis System

LogGuard is a Python-based login security monitoring system that analyzes login logs and detects suspicious login activities based on IP addresses and login failure patterns.

It provides an interactive dashboard for visualizing login statistics, identifying potential brute-force attacks, and generating security reports.

## 🚀 Key Features

- **CSV Log Analysis**: Upload and analyze login records in CSV format.
- **IP Address Validation**: Filter invalid IP addresses.
- **Login Failure Detection**: Identify IP addresses with repeated login failures.
- **Brute-Force Attack Detection**: Detect 5 or more failed login attempts within 1 minute.
- **Risk Classification**: Classify IP addresses into HIGH, MEDIUM, and LOW risk levels.
- **Interactive Dashboard**: Visualize login statistics and security risks using Streamlit and Plotly.
- **Report Generation**: Download detailed CSV reports, summary CSV reports, and text reports.
- **Data Validation**: Handle missing columns, invalid timestamps, and empty datasets.

## 🔍 Risk Classification

| Risk Level | Detection Criteria |
|---|---|
| HIGH | 5 or more failed login attempts within 1 minute |
| MEDIUM | 3 or more total failed login attempts |
| LOW | Does not meet the above criteria |

## 🛠️ Technologies Used

- Python
- Pandas
- Streamlit
- Plotly
- Matplotlib
- IP Address Validation (`ipaddress`)

## 📁 Project Structure

```text
LogGuard/
├── .gitignore
├── main.py
├── dashboard.py
├── README.md
├── requirements.txt
├── login_logs.csv
├── logguard_report.txt
├── screenshots/
│   ├── failed_logins_by_ip.png
│   └── login_result_ratio.png
└── tests/
    ├── test_logs.csv
    ├── success_test.csv
    ├── fail_test.csv
    ├── missing_column_test.csv
    ├── invalid_ip_test.csv
    ├── invalid_timestamp_test.csv
    └── empty_test.csv
```

## 📊 Dashboard

The dashboard provides:

- Login statistics
- Security risk distribution
- IP address analysis
- Login history
- Login analysis graphs
- Downloadable security reports

## ▶️ How to Run

1. Clone this repository.

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

2. Move to the project directory.

```bash
cd LogGuard
```

3. Install the required packages.

```bash
pip install -r requirements.txt
```

4. Run the dashboard.

```bash
streamlit run dashboard.py
```

5. Open the local URL displayed in your terminal.

## 🎯 Project Goal

This project was developed to practice Python programming, data analysis, and basic cybersecurity concepts.

Through LogGuard, I explored login log analysis, IP-based security monitoring, brute-force attack detection, and interactive data visualization.