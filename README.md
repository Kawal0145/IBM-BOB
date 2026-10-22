# AI-Powered Mini SOC

**Hybrid Network Intrusion Detection and Security Incident Monitoring System**

## Project Description

A beginner-friendly **Security Operations Center (SOC)** project that reads network and login log entries, applies rule-based detection, and reports the alerts it finds. Every alert is mapped to a **MITRE ATT&CK** technique and comes with a recommended action.

The project comes in two forms that use the same detection rules and the same data:

- `Kawal_MiniSOC.py`: Python command-line version that prints an alert summary.
- `index.html`: browser dashboard with stat cards, a severity chart, a severity filter, an alerts table and a highlighted log table.

## Dataset

The dataset is a set of 31 hand-made (fake) log entries. Each entry has `time`, `ip`, `user`, `status`, `port` and `action`.

Dataset link: https://github.com/Kawal0145/IBM-BOB/blob/main/sample_logs.js

Two IPs are intentionally suspicious: `192.168.1.99` (5 failed SSH logins) and `10.0.0.55` (probes 5 different ports). The rest is normal activity.

## Detection Rules (Rule-Based, No Machine Learning)

| Rule | Condition | Severity | MITRE ATT&CK |
|------|-----------|----------|--------------|
| Brute Force | Same IP has 5 or more failed logins (10 or more = Critical) | High | T1110 Brute Force |
| Port Scan | Same IP probes 4 or more different ports | Medium | T1046 Network Service Discovery |
| Odd-Hours Login | Successful login before 06:00 or after 22:00 | Low | T1078 Valid Accounts |

## Technologies Used

| Technology | Role |
|------------|------|
| Python 3 (standard library only) | Command-line detection engine and report |
| HTML5 / CSS3 | Dashboard structure and dark theme |
| JavaScript (ES6) | Detection logic and dashboard rendering |
| MITRE ATT&CK | Classification of every alert |
| IBM Bob (AI assistant) | Code generation and documentation |

## Setup and Run Instructions

**Python version**

1. Install Python 3.8 or newer (https://www.python.org/downloads/).
2. No libraries to install. See `requirements.txt`.
3. Open a terminal in the project folder and run:

```
python Kawal_MiniSOC.py
```

**Browser dashboard**

1. Keep `index.html` and `sample_logs.js` in the same folder.
2. Double-click `index.html`. It opens in any modern browser. No server or internet needed.

## Expected Result

| Metric | Value |
|--------|-------|
| Total log entries | 31 |
| Failed logins | 12 |
| Alerts triggered | 2 |
| Brute Force alert (High) | 192.168.1.99 |
| Port Scan alert (Medium) | 10.0.0.55 |
| Rows from suspicious IPs | 10 |

## Folder Structure

```
IBM-BOB/
├── Kawal_MiniSOC.py           Python detection script
├── index.html                 Browser dashboard
├── sample_logs.js             Dataset (31 fake log entries)
├── requirements.txt           Dependency note (none required)
├── Kawal_ProjectReport.docx   Project report
└── README.md                  This file
```

## Limitations and Future Improvements

- Logs are fake and fixed. Next step: parse real files such as Linux `auth.log`.
- Rules use fixed thresholds and no time window. Next step: sliding time windows.
- Replace rules with an anomaly detection model (for example Isolation Forest).
- Add more rules (DDoS, SQL injection) and email or Slack notifications.

## Author

Kawal, IBM Cybersecurity Bootcamp, AI-Powered Mini SOC project.
