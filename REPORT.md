# Project Report
## AI-Powered Mini SOC: Hybrid Network Intrusion Detection and Security Incident Monitoring System

**Course:** IBM Cybersecurity Bootcamp  
**Type:** Beginner Project  
**Technologies:** HTML, CSS, JavaScript  

---

## 1. Introduction

Cyber attacks are becoming more common every day. Organizations use a Security Operations Center (SOC) to monitor their networks, detect threats, and respond to incidents. A key part of every SOC is an Intrusion Detection System (IDS), which automatically watches for suspicious activity in network traffic and login records.

This project builds a small, browser-based Mini SOC dashboard that demonstrates how a basic intrusion detection system works. It uses rule-based detection — simple logical rules — to find two of the most common attack patterns: brute force login attacks and port scanning.

---

## 2. Problem Statement

Small organizations and students often lack access to expensive security tools like IBM QRadar or Splunk. There is a need for a lightweight, easy-to-understand security monitoring tool that can be run without any installation, server, or paid software — and that clearly shows how threat detection works step by step.

---

## 3. Objectives

- Build a working SOC dashboard that runs entirely in a web browser.
- Implement rule-based detection for brute force attacks and port scans.
- Display log data in a readable table with suspicious entries highlighted.
- Show a clear alert summary with severity levels (HIGH / MEDIUM).
- Keep the project beginner-friendly with commented, easy-to-read code.

---

## 4. Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| **HTML5** | Structure of the dashboard (cards, tables, layout) |
| **CSS3** | Dark theme styling, color-coded badges, red row highlights |
| **JavaScript (ES6)** | Detection logic, dynamic rendering of tables and alerts |
| **IBM Bob (AI assistant)** | Code generation, structure planning, and documentation |

No external libraries, frameworks, or Python packages were used. The project runs on any modern browser (Chrome, Firefox, Edge) by simply opening `index.html`.

---

## 5. System Design

The system follows a simple four-step pipeline:

```
[Log Data] → [Detection Rules] → [Alert Generation] → [Dashboard Display]
```

1. **Log Data** — 30 fake log entries are stored in `sample_logs.js` as a JavaScript array. Each entry includes: timestamp, source IP address, username, login status (success/failed), port number, and action type.

2. **Detection Rules** — When the page loads, JavaScript reads all log entries and applies two rules:
   - Count failed logins per IP → trigger Brute Force Alert if count ≥ 5.
   - Count unique ports per IP → trigger Port Scan Alert if unique ports ≥ 4.

3. **Alert Generation** — Any IP that breaks a rule is added to an alerts list with its type, detail, and severity.

4. **Dashboard Display** — The page renders three stat cards, an alerts table, and a full log table. Rows from suspicious IPs are highlighted in red automatically.

---

## 6. Implementation

The project consists of two files:

- **`sample_logs.js`** — Contains 30 hand-crafted log entries. Two IPs are intentionally made suspicious: `192.168.1.99` (5 failed logins) and `10.0.0.55` (port scan across 5 ports). The rest are normal activity from various users.

- **`index.html`** — Contains all HTML structure, CSS styles, and JavaScript logic in one file. The JavaScript has three main functions:
  - `detectBruteForce(logs)` — loops through logs, counts failed logins per IP, returns alerts.
  - `detectPortScan(logs)` — loops through logs, tracks unique ports per IP using a Set, returns alerts.
  - Rendering code — builds the HTML for stat cards, alerts table, and log table using `innerHTML` and `appendChild`.

---

## 7. Detection Rules

### Rule 1 — Brute Force Detection
```
IF count(status == "failed" AND same IP) >= 5
THEN raise alert: "Brute Force", severity: HIGH
```
Rationale: A legitimate user rarely fails login 5 or more times in a short period. Repeated failures from one IP suggest an automated password-guessing attack.

### Rule 2 — Port Scan Detection
```
IF count(unique ports probed by same IP) >= 4
THEN raise alert: "Port Scan", severity: MEDIUM
```
Rationale: Port scanning is a common reconnaissance technique. An attacker probes multiple ports to find open services before launching a targeted attack.

---

## 8. Results

Running the dashboard against the 30 sample log entries produces the following output:

| Metric | Value |
|---|---|
| Total log entries | 30 |
| Failed login attempts | 12 |
| Alerts triggered | 2 |
| Brute Force alerts (HIGH) | 1 — source IP: 192.168.1.99 |
| Port Scan alerts (MEDIUM) | 1 — source IP: 10.0.0.55 |

All 15 log rows from the two suspicious IPs are highlighted in red in the log table. The remaining 15 rows from normal users display with no highlight.

---

## 9. Limitations

- **No real data** — the logs are hand-crafted and do not come from a live network. A real IDS would parse actual log files.
- **Simple rules only** — the detection logic uses fixed thresholds (5 logins, 4 ports). A real attacker could evade these by staying just below the threshold.
- **No time window** — the brute force rule counts all failures in the entire dataset, not within a specific time window (e.g., last 60 seconds). Real systems use sliding windows.
- **No persistence** — alerts are not saved anywhere. Each page reload re-runs detection from scratch.
- **Static dataset** — the dashboard cannot monitor live traffic or receive new log entries in real time.

---

## 10. Future Scope

- **Machine Learning** — replace fixed rules with an anomaly detection model (e.g. Isolation Forest, K-Means clustering) that learns normal behavior and flags deviations.
- **Real log parsing** — load and parse actual system logs such as Linux `auth.log` or Windows Event Logs.
- **Time-windowed detection** — count events only within a rolling time window (e.g., last 5 minutes) to reduce false positives.
- **More attack rules** — add detection for DDoS floods, SQL injection patterns, privilege escalation, and unusual data transfer volumes.
- **Alert notifications** — send alerts via email, SMS, or Slack when a rule is triggered.
- **Backend integration** — connect to a SIEM (Security Information and Event Management) system for centralized log management.

---

## 11. Conclusion

This Mini SOC project demonstrates the core concept of an intrusion detection system in a simple, accessible way. Without installing any software, the dashboard reads log data, applies detection rules, generates alerts, and visualizes results in a clean interface. It covers the fundamental workflow used by real SOC tools — from raw log ingestion to actionable alerts.

The project is a solid starting point for understanding how cybersecurity monitoring works. With further development — adding machine learning, real log sources, and live monitoring — it could evolve into a practical lightweight security tool.

---

*Report prepared as part of the IBM Cybersecurity Bootcamp.*
