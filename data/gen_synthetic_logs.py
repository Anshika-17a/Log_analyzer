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
    start_time = datetime.datetime.now() - datetime.timedelta(days=7)
    
    logs = []
    
    # 1. Brute-force cluster: one user/IP, 5+ failed logins within 10 minutes
    bf_user = "user_brute"
    bf_ip = "10.0.0.99"
    bf_start = start_time + datetime.timedelta(days=1)
    for i in range(6):
        ts = bf_start + datetime.timedelta(minutes=i)
        logs.append([ts.isoformat(), bf_user, "login", "/api/login", bf_ip, "failed"])

    # 2. Off-hours login: 23:00 - 06:00
    off_user = "user_nightowl"
    off_ip = "10.0.0.15"
    off_time = start_time.replace(hour=3, minute=15)
    logs.append([off_time.isoformat(), off_user, "login", "/api/login", off_ip, "success"])

    # 3. Impossible-travel pair: same user, 2 IPs/geos within 10 mins
    imp_user = "user_traveler"
    imp_time1 = start_time + datetime.timedelta(days=2, hours=12)
    imp_time2 = imp_time1 + datetime.timedelta(minutes=5)
    logs.append([imp_time1.isoformat(), imp_user, "login", "/api/login", random.choice(IP_MAP["US"]), "success"])
    logs.append([imp_time2.isoformat(), imp_user, "login", "/api/login", random.choice(IP_MAP["RU"]), "success"])

    # 4. Privilege escalation event
    priv_user = "user_hacker"
    priv_time = start_time + datetime.timedelta(days=3)
    logs.append([priv_time.isoformat(), priv_user, "privilege_escalation", "/admin/settings", random.choice(IP_MAP["US"]), "success"])

    # 5. Export burst: export right after blocked status event
    exp_user = "user_exfiltrator"
    exp_time_blocked = start_time + datetime.timedelta(days=4)
    exp_time_export = exp_time_blocked + datetime.timedelta(seconds=10)
    logs.append([exp_time_blocked.isoformat(), exp_user, "read", "/api/data", random.choice(IP_MAP["US"]), "blocked"])
    logs.append([exp_time_export.isoformat(), exp_user, "export", "/api/export", random.choice(IP_MAP["US"]), "success"])

    # Also an export burst
    burst_time = start_time + datetime.timedelta(days=5)
    for i in range(105):
        logs.append([(burst_time + datetime.timedelta(seconds=i)).isoformat(), "user_leaker", "export", "/api/export", "10.0.0.200", "success"])

    # 6. Recon / Access Denial Spray
    recon_user = "user_scanner"
    recon_time = start_time + datetime.timedelta(days=6)
    for i in range(12):
        ts = recon_time + datetime.timedelta(minutes=i*2)
        logs.append([ts.isoformat(), recon_user, "read", "/api/data", random.choice(IP_MAP["US"]), "blocked"])

    # 7. Dormant Account Login
    dormant_user = "user_sleepy"
    dormant_time1 = start_time - datetime.timedelta(days=35) # 35 days ago
    dormant_time2 = start_time + datetime.timedelta(days=6, hours=12) # present
    logs.append([dormant_time1.isoformat(), dormant_user, "login", "/api/login", random.choice(IP_MAP["US"]), "success"])
    logs.append([dormant_time2.isoformat(), dormant_user, "login", "/api/login", random.choice(IP_MAP["US"]), "success"])

    # Fill the rest with benign
    current_time = start_time
    while len(logs) < num_rows:
        logs.append(generate_benign_event(current_time))
        current_time += datetime.timedelta(minutes=random.randint(1, 10))

    # Sort by timestamp
    logs.sort(key=lambda x: x[0])

    # Truncate to num_rows in case we went over
    logs = logs[:num_rows]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "user_id", "event_type", "resource", "src_ip", "status"])
        writer.writerows(logs)
    
    print(f"Generated {len(logs)} rows in {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=500)
    parser.add_argument("--out", type=str, default="data/sample_logs.csv")
    args = parser.parse_args()
    
    generate_synthetic_logs(args.rows, args.out)
