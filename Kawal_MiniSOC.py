"""
AI-Powered Mini SOC
Hybrid Network Intrusion Detection and Security Incident Monitoring System

Python version of the Mini SOC dashboard (index.html).
Loads sample login/network logs, runs rule-based detection, maps every
alert to MITRE ATT&CK and prints an alert summary.
Only the Python standard library is used.

Run with:  python Kawal_MiniSOC.py
Dataset:   https://github.com/Kawal0145/IBM-BOB/blob/main/sample_logs.js
"""
from collections import defaultdict
import re

# ---------------------------------------------------------------------
# 1. LOG DATA (same 31 entries as sample_logs.js)
# ---------------------------------------------------------------------
def L(time, ip, user, status, port, action):
    return {"time": f"2024-06-01 {time}", "ip": ip, "user": user,
            "status": status, "port": port, "action": action}

LOGS = [
    # --- Normal successful logins ---
    L("08:01:10", "192.168.1.10", "alice", "success", 22,   "SSH Login"),
    L("08:03:44", "192.168.1.11", "bob",   "success", 443,  "HTTPS Access"),
    L("08:07:22", "10.0.0.5",     "carol", "success", 80,   "HTTP Access"),
    L("08:12:05", "192.168.1.20", "dave",  "success", 3389, "RDP Login"),
    L("08:15:30", "10.0.0.8",     "eve",   "success", 22,   "SSH Login"),
    # --- Brute force: 5 failed logins from 192.168.1.99 ---
    L("09:00:01", "192.168.1.99", "admin", "failed", 22, "SSH Login"),
    L("09:00:08", "192.168.1.99", "admin", "failed", 22, "SSH Login"),
    L("09:00:15", "192.168.1.99", "admin", "failed", 22, "SSH Login"),
    L("09:00:22", "192.168.1.99", "admin", "failed", 22, "SSH Login"),
    L("09:00:29", "192.168.1.99", "admin", "failed", 22, "SSH Login"),
    # --- Port scan: same IP probing 5 different ports ---
    L("09:30:01", "10.0.0.55", "-", "failed", 21,   "FTP Probe"),
    L("09:30:02", "10.0.0.55", "-", "failed", 22,   "SSH Probe"),
    L("09:30:03", "10.0.0.55", "-", "failed", 23,   "Telnet Probe"),
    L("09:30:04", "10.0.0.55", "-", "failed", 3306, "MySQL Probe"),
    L("09:30:05", "10.0.0.55", "-", "failed", 8080, "HTTP-Alt Probe"),
    # --- More normal activity ---
    L("10:00:00", "192.168.1.30", "frank", "success", 443,  "HTTPS Access"),
    L("10:05:11", "192.168.1.31", "grace", "success", 80,   "HTTP Access"),
    L("10:10:45", "10.0.0.12",    "heidi", "success", 22,   "SSH Login"),
    L("10:15:00", "10.0.0.13",    "ivan",  "success", 3389, "RDP Login"),
    L("10:20:33", "192.168.1.40", "judy",  "success", 443,  "HTTPS Access"),
    # --- Two isolated failed logins (not enough for brute force) ---
    L("10:30:00", "172.16.0.7", "mallory", "failed", 22, "SSH Login"),
    L("10:31:00", "172.16.0.7", "mallory", "failed", 22, "SSH Login"),
    # --- More normal activity ---
    L("11:00:00", "192.168.1.50", "oscar",  "success", 80,   "HTTP Access"),
    L("11:05:00", "192.168.1.51", "peggy",  "success", 443,  "HTTPS Access"),
    L("11:10:00", "10.0.0.20",    "quinn",  "success", 22,   "SSH Login"),
    L("11:15:00", "10.0.0.21",    "rupert", "success", 3306, "DB Connect"),
    L("11:20:00", "192.168.1.60", "sybil",  "success", 443,  "HTTPS Access"),
    L("11:25:00", "192.168.1.61", "trent",  "success", 80,   "HTTP Access"),
    L("11:30:00", "10.0.0.30",    "uma",    "success", 22,   "SSH Login"),
    L("11:35:00", "10.0.0.31",    "victor", "success", 443,  "HTTPS Access"),
    L("11:40:00", "192.168.1.70", "wendy",  "success", 80,   "HTTP Access"),
]

# ---------------------------------------------------------------------
# 2. MITRE ATT&CK MAPPING
# ---------------------------------------------------------------------
MITRE = {
    "Brute Force":     {"id": "T1110", "name": "Brute Force",               "tactic": "Credential Access"},
    "Port Scan":       {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "Odd-Hours Login": {"id": "T1078", "name": "Valid Accounts",            "tactic": "Initial Access"},
}

# ---------------------------------------------------------------------
# 3. DETECTION RULES (rule-based, no machine learning)
# ---------------------------------------------------------------------
def detect_brute_force(logs, threshold=5):
    """Rule 1: same IP has `threshold` or more failed logins.
    10+ failures is CRITICAL, otherwise HIGH.
    Port probes (user "-") are not logins, so they are ignored here."""
    fail_counts = defaultdict(int)
    for log in logs:
        if log["status"] == "failed" and log["user"] != "-":
            fail_counts[log["ip"]] += 1
    alerts = []
    for ip, count in fail_counts.items():
        if count >= threshold:
            alerts.append({
                "type": "Brute Force",
                "ip": ip,
                "detail": f"{count} failed login attempts",
                "severity": "CRITICAL" if count >= 10 else "HIGH",
                "action": "Block the IP, enable account lockout and MFA.",
            })
    return alerts


def detect_port_scan(logs, threshold=4):
    """Rule 2: same IP probes `threshold` or more different ports."""
    ports_by_ip = defaultdict(set)
    for log in logs:
        ports_by_ip[log["ip"]].add(log["port"])
    alerts = []
    for ip, ports in ports_by_ip.items():
        if len(ports) >= threshold:
            alerts.append({
                "type": "Port Scan",
                "ip": ip,
                "detail": f"{len(ports)} different ports probed: "
                          + ", ".join(str(p) for p in sorted(ports)),
                "severity": "MEDIUM",
                "action": "Rate-limit or block the IP, close unused ports.",
            })
    return alerts


def detect_odd_hours(logs):
    """Rule 3: successful login before 06:00 or after 22:00."""
    alerts = []
    for log in logs:
        if log["status"] != "success":
            continue
        match = re.search(r" (\d{2}):\d{2}:\d{2}", log["time"])
        if match:
            hour = int(match.group(1))
            if hour < 6 or hour >= 22:
                alerts.append({
                    "type": "Odd-Hours Login",
                    "ip": log["ip"],
                    "detail": f"User {log['user']} logged in at {log['time']}",
                    "severity": "LOW",
                    "action": "Confirm with the user; reset password if not them.",
                })
    return alerts

# ---------------------------------------------------------------------
# 4. REPORTING
# ---------------------------------------------------------------------
def print_report(logs, alerts):
    failed = sum(1 for l in logs if l["status"] == "failed")
    suspicious_ips = {a["ip"] for a in alerts}
    suspicious_rows = sum(1 for l in logs if l["ip"] in suspicious_ips)

    line = "=" * 72
    print(line)
    print("  AI-POWERED MINI SOC - INTRUSION DETECTION SUMMARY")
    print(line)
    print(f"  Total log entries   : {len(logs)}")
    print(f"  Failed logins       : {failed}")
    print(f"  Alerts triggered    : {len(alerts)}")
    print(f"  Suspicious IPs      : {len(suspicious_ips)}")
    print(f"  Rows from those IPs : {suspicious_rows}")
    print(line)

    print("\n  ALERTS BY SEVERITY")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for a in alerts if a["severity"] == level)
        print(f"    {level:<9}: {count} {'#' * count}")

    print("\n  ALERT DETAILS")
    print("-" * 72)
    if not alerts:
        print("  No alerts detected.")
    for i, a in enumerate(alerts, 1):
        m = MITRE[a["type"]]
        print(f"  [{i}] {a['type']}  |  Severity: {a['severity']}")
        print(f"      Source IP : {a['ip']}")
        print(f"      Detail    : {a['detail']}")
        print(f"      MITRE     : {m['id']} {m['name']} ({m['tactic']})")
        print(f"                  https://attack.mitre.org/techniques/{m['id']}/")
        print(f"      Action    : {a['action']}")
        print("-" * 72)


def main():
    alerts = (
        detect_brute_force(LOGS)
        + detect_port_scan(LOGS)
        + detect_odd_hours(LOGS)
    )
    print_report(LOGS, alerts)


if __name__ == "__main__":
    main()
