"""
Synthetic log generator for Security Log Analyzer demo.

Generates a CSV with:
  - A rich APT (Advanced Persistent Threat) campaign for ONE user that
    deliberately triggers all 7 detection rules in sequence:
    1. Brute Force (brute_force_001)
    2. Impossible Travel (impossible_travel_001)
    3. Privilege Escalation (priv_esc_001)
    4. Reconnaissance (recon_001)
    5. Off-Hours Access (off_hours_001)
    6. Data Exfiltration Burst (exfil_burst_001)
    7. Dormant Account (dormant_account_001)
  - Additional single-rule users so the MITRE matrix has breadth.
  - Benign background traffic to fill to num_rows.
"""
import argparse
import csv
import random
import datetime

USERS = [f"user_{i}" for i in range(1, 21)]
RESOURCES = ["/api/login", "/api/data", "/api/profile", "/api/export", "/admin/settings"]
STATUSES = ["success", "failed", "blocked"]
EVENT_TYPES = ["login", "read", "write", "export", "logout"]

IP_MAP = {
    "US": ["10.0.0.1", "10.0.0.2", "10.0.1.50"],
    "UK": ["192.168.1.100"],
    "RU": ["185.2.0.1", "185.2.1.20"],
    "NG": ["41.7.0.5", "41.7.1.10"]
}


def generate_benign_event(current_time):
    user = random.choice(USERS)
    event_type = random.choice(["login", "read", "write", "logout"])
    resource = random.choice(["/api/data", "/api/profile"])
    ip = random.choice(IP_MAP["US"])
    status = random.choices(["success", "failed"], weights=[95, 5])[0]
    return [current_time.isoformat(), user, event_type, resource, ip, status]


def generate_synthetic_logs(num_rows, output_file):
    base = datetime.datetime(2026, 9, 2, 8, 0, 0)  # Fixed base for reproducibility
    logs = []

    # ── APT CAMPAIGN for "apt_user_1": all 7 rules in one 24-hour window ──────
    # The dormant-account rule needs a prior login 30+ days ago
    dormant_anchor = base - datetime.timedelta(days=40)
    logs.append([dormant_anchor.isoformat(), "apt_user_1", "login", "/api/login",
                 IP_MAP["US"][0], "success"])

    # Day 0, 02:00 — Off-hours login (triggers off_hours_001: hour < 6)
    t = base.replace(hour=2, minute=0)
    logs.append([t.isoformat(), "apt_user_1", "login", "/api/login", IP_MAP["US"][0], "success"])

    # Day 0, 02:01-02:06 — Brute force: 6 failed logins in 10 min (triggers brute_force_001)
    for i in range(6):
        ts = t + datetime.timedelta(minutes=1, seconds=i * 30)
        logs.append([ts.isoformat(), "apt_user_1", "login", "/api/login", IP_MAP["US"][0], "failed"])

    # Day 0, 02:07 — Impossible travel: login from Russia within 5 min (triggers impossible_travel_001)
    ts = t + datetime.timedelta(minutes=7)
    logs.append([ts.isoformat(), "apt_user_1", "login", "/api/login", IP_MAP["RU"][0], "success"])

    # Day 0, 02:10 — Privilege escalation (triggers priv_esc_001)
    ts = t + datetime.timedelta(minutes=10)
    logs.append([ts.isoformat(), "apt_user_1", "privilege_escalation", "/admin/settings",
                 IP_MAP["US"][0], "success"])

    # Day 0, 02:12-02:22 — Recon: 12 blocked reads within 10 min (triggers recon_001)
    for i in range(12):
        ts = t + datetime.timedelta(minutes=12, seconds=i * 50)
        logs.append([ts.isoformat(), "apt_user_1", "read", "/api/data", IP_MAP["US"][0], "blocked"])

    # Day 0, 02:23 — Blocked event followed immediately by export (triggers exfil_burst_001 by prev_status)
    ts_blocked = t + datetime.timedelta(minutes=23)
    ts_export  = ts_blocked + datetime.timedelta(seconds=5)
    logs.append([ts_blocked.isoformat(), "apt_user_1", "read", "/api/data", IP_MAP["US"][0], "blocked"])
    logs.append([ts_export.isoformat(),  "apt_user_1", "export", "/api/export", IP_MAP["US"][0], "success"])

    # Day 0, 02:24 — Export burst: 105 exports in 2 min (triggers exfil_burst_001 by count)
    burst_t = ts_export + datetime.timedelta(seconds=30)
    for i in range(110):
        ts = burst_t + datetime.timedelta(seconds=i)
        logs.append([ts.isoformat(), "apt_user_1", "export", "/api/export", IP_MAP["US"][0], "success"])

    # Day 0, 02:27 — Dormant account re-login (triggers dormant_account_001 because >30 days gap from anchor)
    ts = t + datetime.timedelta(minutes=27)
    logs.append([ts.isoformat(), "apt_user_1", "login", "/api/login", IP_MAP["UK"][0], "success"])

    # ── Single-rule specialist users for MITRE matrix breadth ────────────────

    # user_brute: pure brute force
    bf_start = base + datetime.timedelta(hours=4)
    for i in range(6):
        logs.append([(bf_start + datetime.timedelta(minutes=i)).isoformat(),
                     "user_brute", "login", "/api/login", "10.0.0.99", "failed"])

    # user_nightowl: off-hours login
    logs.append([(base.replace(hour=3, minute=30)).isoformat(),
                 "user_nightowl", "login", "/api/login", "10.0.0.15", "success"])

    # user_traveler: impossible travel
    imp_t = base + datetime.timedelta(hours=6)
    logs.append([(imp_t).isoformat(), "user_traveler", "login", "/api/login", IP_MAP["US"][1], "success"])
    logs.append([(imp_t + datetime.timedelta(minutes=3)).isoformat(),
                 "user_traveler", "login", "/api/login", IP_MAP["NG"][0], "success"])

    # user_hacker: privilege escalation
    logs.append([(base + datetime.timedelta(hours=8)).isoformat(),
                 "user_hacker", "privilege_escalation", "/admin/settings", IP_MAP["US"][0], "success"])

    # user_exfiltrator: blocked + immediate export
    exp_t = base + datetime.timedelta(hours=10)
    logs.append([exp_t.isoformat(), "user_exfiltrator", "read", "/api/data", IP_MAP["US"][0], "blocked"])
    logs.append([(exp_t + datetime.timedelta(seconds=8)).isoformat(),
                 "user_exfiltrator", "export", "/api/export", IP_MAP["US"][0], "success"])

    # user_leaker: export burst
    leak_t = base + datetime.timedelta(hours=12)
    for i in range(110):
        logs.append([(leak_t + datetime.timedelta(seconds=i)).isoformat(),
                     "user_leaker", "export", "/api/export", "10.0.0.200", "success"])

    # user_scanner: recon / blocked spray
    scan_t = base + datetime.timedelta(hours=14)
    for i in range(13):
        logs.append([(scan_t + datetime.timedelta(minutes=i * 2)).isoformat(),
                     "user_scanner", "read", "/api/data", IP_MAP["US"][1], "blocked"])

    # user_sleepy: dormant account (35 days idle then re-login)
    dormant_first = base - datetime.timedelta(days=36)
    logs.append([dormant_first.isoformat(), "user_sleepy", "login", "/api/login", IP_MAP["US"][0], "success"])
    logs.append([(base + datetime.timedelta(hours=16)).isoformat(),
                 "user_sleepy", "login", "/api/login", IP_MAP["US"][0], "success"])

    # ── Benign background traffic ─────────────────────────────────────────────
    current = base
    while len(logs) < num_rows:
        logs.append(generate_benign_event(current))
        current += datetime.timedelta(minutes=random.randint(1, 10))

    # Sort chronologically and truncate
    logs.sort(key=lambda x: x[0])
    logs = logs[:num_rows]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "user_id", "event_type", "resource", "src_ip", "status"])
        writer.writerows(logs)

    print(f"Generated {len(logs)} rows in {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=500)
    parser.add_argument("--out",  type=str, default="data/sample_logs.csv")
    args = parser.parse_args()
    generate_synthetic_logs(args.rows, args.out)
