"""
Live Attack Scenario Simulator for Security Log Analyzer.

Generates realistic raw security telemetry for 3 standardized benchmark scenarios:
1. 'apt29': Multi-stage Advanced Persistent Threat breach (dormant account, off-hours, brute force,
            impossible travel, privilege escalation, recon spray, and bulk exfiltration).
2. 'insider': Malicious insider data exfiltration (off-hours sensitive data access, bulk export burst,
              and ML behavioral anomaly deviation).
3. 'benign': Clean baseline enterprise workday (normal employee operations during working hours, zero attacks).
"""
import io
import csv
import random
import datetime
from typing import List, Dict, Any, Tuple


IP_POOLS = {
    "US_CORP": ["10.0.0.1", "10.0.0.15", "10.0.1.50"],
    "US_REMOTE": ["192.168.1.100", "192.168.1.105"],
    "RU_ADVERSARY": ["185.2.0.1", "185.2.1.20"],
    "TOR_EXIT": ["198.51.100.44", "203.0.113.15"]
}


def build_scenario_csv(scenario: str) -> Tuple[io.BytesIO, str, List[Dict[str, str]]]:
    """
    Returns (bytes_buffer, filename, sample_stream_lines).
    """
    base = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) - datetime.timedelta(days=1)
    logs = []

    if scenario == "apt29":
        filename = "simulated_apt29_campaign.csv"
        # 1. Dormant anchor 35 days ago
        anchor = base - datetime.timedelta(days=35)
        logs.append([anchor.isoformat(), "apt_user_1", "login", "/api/login", IP_POOLS["US_CORP"][0], "success"])

        # 2. Day 0, 02:00 UTC: Off-hours login (Rule: off_hours_001)
        t0 = base.replace(hour=2, minute=0, second=0)
        logs.append([t0.isoformat(), "apt_user_1", "login", "/api/login", IP_POOLS["US_CORP"][0], "success"])

        # 3. 02:01-02:05 UTC: Brute force login sequence (Rule: brute_force_001)
        for i in range(6):
            ts = t0 + datetime.timedelta(minutes=1, seconds=i * 30)
            logs.append([ts.isoformat(), "apt_user_1", "login", "/api/login", IP_POOLS["US_CORP"][0], "failed"])

        # 4. 02:07 UTC: Impossible travel from Moscow IP within 5 min (Rule: impossible_travel_001)
        ts_ru = t0 + datetime.timedelta(minutes=7)
        logs.append([ts_ru.isoformat(), "apt_user_1", "login", "/api/login", IP_POOLS["RU_ADVERSARY"][0], "success"])

        # 5. 02:10 UTC: Privilege Escalation to root (Rule: priv_esc_001)
        ts_pe = t0 + datetime.timedelta(minutes=10)
        logs.append([ts_pe.isoformat(), "apt_user_1", "privilege_escalation", "/admin/settings", IP_POOLS["US_CORP"][0], "success"])

        # 6. 02:12-02:20 UTC: Reconnaissance spray (12 blocked accesses) (Rule: recon_001)
        for i in range(12):
            ts_recon = t0 + datetime.timedelta(minutes=12, seconds=i * 40)
            logs.append([ts_recon.isoformat(), "apt_user_1", "read", f"/api/internal/subnet_{i}", IP_POOLS["US_CORP"][0], "blocked"])

        # 7. 02:22 UTC: Blocked access immediately followed by export
        ts_b = t0 + datetime.timedelta(minutes=22)
        logs.append([ts_b.isoformat(), "apt_user_1", "read", "/api/financial/q4_ledger", IP_POOLS["US_CORP"][0], "blocked"])
        logs.append([(ts_b + datetime.timedelta(seconds=8)).isoformat(), "apt_user_1", "export", "/api/financial/q4_ledger", IP_POOLS["US_CORP"][0], "success"])

        # 8. 02:24 UTC: Exfiltration burst: 110 rapid export records (Rule: exfil_burst_001)
        burst_start = t0 + datetime.timedelta(minutes=24)
        for i in range(110):
            ts_ex = burst_start + datetime.timedelta(seconds=i)
            logs.append([ts_ex.isoformat(), "apt_user_1", "export", "/api/database/customers_dump", IP_POOLS["US_CORP"][0], "success"])

        # 9. 02:28 UTC: Dormant account reactivation flag (Rule: dormant_account_001)
        logs.append([(t0 + datetime.timedelta(minutes=28)).isoformat(), "apt_user_1", "login", "/api/login", IP_POOLS["US_REMOTE"][0], "success"])

        # Add background traffic
        for i in range(120):
            bg_time = base + datetime.timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59))
            logs.append([
                bg_time.isoformat(),
                f"worker_{random.randint(1, 10)}",
                random.choice(["login", "read", "write", "logout"]),
                random.choice(["/api/dashboard", "/api/docs", "/api/projects"]),
                random.choice(IP_POOLS["US_CORP"]),
                "success"
            ])

    elif scenario == "insider":
        filename = "simulated_insider_threat.csv"
        # Normal baseline for insider_dev during working hours
        for day in range(3):
            d_time = base - datetime.timedelta(days=3 - day, hours=random.randint(2, 6))
            for _ in range(15):
                logs.append([
                    d_time.isoformat(),
                    "insider_dev",
                    "read",
                    "/api/sourcecode/repo",
                    IP_POOLS["US_CORP"][1],
                    "success"
                ])
                d_time += datetime.timedelta(minutes=random.randint(5, 20))

        # Night of the breach: 02:45 AM anomalous off-hours exfiltration burst
        t_breach = base.replace(hour=2, minute=45, second=0)
        logs.append([t_breach.isoformat(), "insider_dev", "login", "/api/login", IP_POOLS["US_CORP"][1], "success"])
        logs.append([(t_breach + datetime.timedelta(minutes=2)).isoformat(), "insider_dev", "read", "/admin/confidential_patents", IP_POOLS["US_CORP"][1], "blocked"])

        # High volume exfiltration burst (115 files)
        t_exfil = t_breach + datetime.timedelta(minutes=4)
        for i in range(115):
            logs.append([
                (t_exfil + datetime.timedelta(seconds=i)).isoformat(),
                "insider_dev",
                "export",
                f"/api/intellectual_property/file_{i}.tar.gz",
                IP_POOLS["US_CORP"][1],
                "success"
            ])

        # Benign background
        for i in range(80):
            bg_time = base + datetime.timedelta(hours=random.randint(9, 17), minutes=random.randint(0, 59))
            logs.append([
                bg_time.isoformat(),
                f"staff_{random.randint(1, 8)}",
                random.choice(["read", "write"]),
                "/api/helpdesk/tickets",
                random.choice(IP_POOLS["US_CORP"]),
                "success"
            ])

    else:  # "benign"
        filename = "simulated_benign_traffic.csv"
        # 160 purely normal, business-hours events
        curr = base.replace(hour=9, minute=0, second=0)
        users = ["alice", "bob", "carol", "dave", "eva", "frank", "grace"]
        for _ in range(160):
            user = random.choice(users)
            ev = random.choice(["login", "read", "write", "logout"])
            status = "success" if random.random() > 0.03 else "failed"
            logs.append([
                curr.isoformat(),
                user,
                ev,
                random.choice(["/api/crm", "/api/portal", "/api/email"]),
                random.choice(IP_POOLS["US_CORP"]),
                status
            ])
            curr += datetime.timedelta(seconds=random.randint(45, 180))

    # Sort chronologically for CSV output
    logs.sort(key=lambda x: x[0])

    # Build rich sample stream for live animated terminal ticker
    sample_stream = []
    if scenario == "apt29":
        # Skip 35-day-old anchor for ticker, highlight the active breach kill chain
        stream_pool = [r for r in logs if r[1] == "apt_user_1" and r != logs[0]][:28]
        if not stream_pool:
            stream_pool = logs[:28]
    elif scenario == "insider":
        # 4 baseline events followed by the unauthorized access and exfiltration burst
        baseline_sample = [r for r in logs if r[1] == "insider_dev" and "confidential" not in r[3] and r[2] == "read"][:4]
        breach_sample = [r for r in logs if r[1] == "insider_dev" and ("confidential" in r[3] or r[2] in ("export", "login") or r[5] == "blocked")][:24]
        stream_pool = baseline_sample + breach_sample
    else:
        stream_pool = logs[:25]

    for row in stream_pool:
        ts, user, event, resource, ip, status = row
        tag = "TELEMETRY"
        sev = "clean"
        
        if "185.2.0.1" in ip:
            tag = "IMPOSSIBLE TRAVEL (MOSCOW)"
            sev = "critical"
        elif event == "privilege_escalation":
            tag = "PRIVILEGE ESCALATION (ROOT)"
            sev = "critical"
        elif event == "export" and ("dump" in resource or "intellectual_property" in resource or "ledger" in resource):
            tag = "DATA EXFILTRATION"
            sev = "critical"
        elif status == "failed" and event == "login":
            tag = "BRUTE FORCE AUTH"
            sev = "high"
        elif status == "blocked" or "confidential" in resource:
            tag = "UNAUTHORIZED ACCESS"
            sev = "high"
        elif event == "export":
            tag = "BULK EXPORT"
            sev = "medium"
        elif status == "success":
            tag = "AUDIT OK"
            sev = "clean"

        sample_stream.append({
            "ts": ts,
            "user": user,
            "event": event,
            "resource": resource,
            "ip": ip,
            "status": status,
            "tag": tag,
            "severity": sev
        })

    # Write to in-memory CSV
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["timestamp", "user_id", "event_type", "resource", "src_ip", "status"])
    writer.writerows(logs)

    buf = io.BytesIO(out.getvalue().encode("utf-8"))
    return buf, filename, sample_stream

