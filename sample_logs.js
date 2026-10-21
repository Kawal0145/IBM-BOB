// sample_logs.js
// Fake network/login log entries for the Mini SOC dashboard.
// Each entry has: time, ip, user, status, port, action.

const LOGS = [
  // --- Normal successful logins ---
  { time: "2024-06-01 08:01:10", ip: "192.168.1.10", user: "alice",   status: "success", port: 22,   action: "SSH Login" },
  { time: "2024-06-01 08:03:44", ip: "192.168.1.11", user: "bob",     status: "success", port: 443,  action: "HTTPS Access" },
  { time: "2024-06-01 08:07:22", ip: "10.0.0.5",     user: "carol",   status: "success", port: 80,   action: "HTTP Access" },
  { time: "2024-06-01 08:12:05", ip: "192.168.1.20", user: "dave",    status: "success", port: 3389, action: "RDP Login" },
  { time: "2024-06-01 08:15:30", ip: "10.0.0.8",     user: "eve",     status: "success", port: 22,   action: "SSH Login" },

  // --- Brute force: 5 failed logins from 192.168.1.99 ---
  { time: "2024-06-01 09:00:01", ip: "192.168.1.99", user: "admin",   status: "failed",  port: 22,   action: "SSH Login" },
  { time: "2024-06-01 09:00:08", ip: "192.168.1.99", user: "admin",   status: "failed",  port: 22,   action: "SSH Login" },
  { time: "2024-06-01 09:00:15", ip: "192.168.1.99", user: "admin",   status: "failed",  port: 22,   action: "SSH Login" },
  { time: "2024-06-01 09:00:22", ip: "192.168.1.99", user: "admin",   status: "failed",  port: 22,   action: "SSH Login" },
  { time: "2024-06-01 09:00:29", ip: "192.168.1.99", user: "admin",   status: "failed",  port: 22,   action: "SSH Login" },

  // --- Port scan: same IP probing 5 different ports ---
  { time: "2024-06-01 09:30:01", ip: "10.0.0.55",    user: "-",       status: "failed",  port: 21,   action: "FTP Probe" },
  { time: "2024-06-01 09:30:02", ip: "10.0.0.55",    user: "-",       status: "failed",  port: 22,   action: "SSH Probe" },
  { time: "2024-06-01 09:30:03", ip: "10.0.0.55",    user: "-",       status: "failed",  port: 23,   action: "Telnet Probe" },
  { time: "2024-06-01 09:30:04", ip: "10.0.0.55",    user: "-",       status: "failed",  port: 3306, action: "MySQL Probe" },
  { time: "2024-06-01 09:30:05", ip: "10.0.0.55",    user: "-",       status: "failed",  port: 8080, action: "HTTP-Alt Probe" },

  // --- More normal activity ---
  { time: "2024-06-01 10:00:00", ip: "192.168.1.30", user: "frank",   status: "success", port: 443,  action: "HTTPS Access" },
  { time: "2024-06-01 10:05:11", ip: "192.168.1.31", user: "grace",   status: "success", port: 80,   action: "HTTP Access" },
  { time: "2024-06-01 10:10:45", ip: "10.0.0.12",    user: "heidi",   status: "success", port: 22,   action: "SSH Login" },
  { time: "2024-06-01 10:15:00", ip: "10.0.0.13",    user: "ivan",    status: "success", port: 3389, action: "RDP Login" },
  { time: "2024-06-01 10:20:33", ip: "192.168.1.40", user: "judy",    status: "success", port: 443,  action: "HTTPS Access" },

  // --- A couple of isolated failed logins (not enough for brute force) ---
  { time: "2024-06-01 10:30:00", ip: "172.16.0.7",   user: "mallory", status: "failed",  port: 22,   action: "SSH Login" },
  { time: "2024-06-01 10:31:00", ip: "172.16.0.7",   user: "mallory", status: "failed",  port: 22,   action: "SSH Login" },

  // --- More normal activity ---
  { time: "2024-06-01 11:00:00", ip: "192.168.1.50", user: "oscar",   status: "success", port: 80,   action: "HTTP Access" },
  { time: "2024-06-01 11:05:00", ip: "192.168.1.51", user: "peggy",   status: "success", port: 443,  action: "HTTPS Access" },
  { time: "2024-06-01 11:10:00", ip: "10.0.0.20",    user: "quinn",   status: "success", port: 22,   action: "SSH Login" },
  { time: "2024-06-01 11:15:00", ip: "10.0.0.21",    user: "rupert",  status: "success", port: 3306, action: "DB Connect" },
  { time: "2024-06-01 11:20:00", ip: "192.168.1.60", user: "sybil",   status: "success", port: 443,  action: "HTTPS Access" },
  { time: "2024-06-01 11:25:00", ip: "192.168.1.61", user: "trent",   status: "success", port: 80,   action: "HTTP Access" },
  { time: "2024-06-01 11:30:00", ip: "10.0.0.30",    user: "uma",     status: "success", port: 22,   action: "SSH Login" },
  { time: "2024-06-01 11:35:00", ip: "10.0.0.31",    user: "victor",  status: "success", port: 443,  action: "HTTPS Access" },
  { time: "2024-06-01 11:40:00", ip: "192.168.1.70", user: "wendy",   status: "success", port: 80,   action: "HTTP Access" },
];
