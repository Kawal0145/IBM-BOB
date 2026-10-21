# AI-Powered Mini SOC
### Hybrid Network Intrusion Detection and Security Incident Monitoring System

A beginner-friendly, browser-based **Security Operations Center (SOC)** dashboard.  
It loads fake network and login log entries, runs rule-based detection, and displays alerts and statistics — all inside a single HTML file with no installation required.

---

## Features

- 📊 **Stat cards** — total log entries, failed logins, and alert count at a glance
- 🚨 **Alerts table** — lists every triggered alert with type, source IP, detail, and severity badge (HIGH / MEDIUM)
- 📋 **Full log table** — all 30 log entries displayed in a table
- 🔴 **Red highlighting** — rows belonging to suspicious IPs are automatically highlighted in red
- ⚡ **No installation** — pure HTML, CSS and JavaScript; opens directly in any browser

---

## Detection Rules (Rule-Based, No Machine Learning)

| Rule | Condition | Severity |
|---|---|---|
| **Brute Force Alert** | Same IP has 5 or more failed login attempts | 🔴 HIGH |
| **Port Scan Alert** | Same IP probes 4 or more different ports | 🟡 MEDIUM |

Suspicious IPs in the sample data:
- `192.168.1.99` — 5 failed SSH logins → **Brute Force Alert**
- `10.0.0.55` — probes 5 different ports (21, 22, 23, 3306, 8080) → **Port Scan Alert**

---

## Folder Structure

```
IBM-BOB/
├── index.html          ← Dashboard (HTML + CSS + JavaScript in one file)
├── sample_logs.js      ← 30 fake log entries as a JavaScript array
├── requirements.txt    ← Dependency note (none required)
├── README.md           ← This file
└── REPORT.md           ← Project report
```

---

## How to Run

1. Open the `IBM-BOB` folder in **File Explorer**.
2. **Double-click `index.html`**.
3. The dashboard opens in your default browser — done.

> No Python, no Node.js, no server, no internet connection required.

---

## Technologies Used

| Technology | Role |
|---|---|
| HTML5 | Page structure and tables |
| CSS3 | Dark theme styling and layout |
| JavaScript (ES6) | Detection logic and dynamic rendering |

---

## Future Improvements

- 🤖 **Machine Learning** — replace if/else rules with a trained anomaly detection model (e.g. Isolation Forest)
- 📁 **Real log files** — parse actual system logs (auth.log, Windows Event Logs) instead of hand-crafted data
- 📡 **Live monitoring** — connect to a log stream or SIEM API for real-time alerts
- 📧 **Notifications** — send email or Slack alerts when a rule is triggered
- 🗂️ **More rules** — add detection for DDoS, SQL injection attempts, and privilege escalation

---

## Author

IBM Cybersecurity Bootcamp — AI-Powered Mini SOC Project
