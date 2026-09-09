import pandas as pd
import numpy as np
from app.detection.mitre_mapping import get_mitre_info

IP_COUNTRY_MAP = {
    "10.0.": "US",
    "192.168.": "UK",
    "185.2.": "RU",
    "41.7.": "NG"
}

def get_country(ip):
    if not ip or pd.isna(ip): return "Unknown"
    ip_str = str(ip)
    for prefix, country in IP_COUNTRY_MAP.items():
        if ip_str.startswith(prefix):
            return country
    return "Unknown"

def _create_alert(row, ts, rule_id, rule_name, severity, points, evidence):
    mitre = get_mitre_info(rule_id)
    return ({
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "points": points,
        "user": str(row["user"]),
        "ip": str(row["ip"]),
        "timestamp": ts.isoformat() if isinstance(ts, pd.Timestamp) else str(ts),
        "log_id": int(row["id"]),
        "mitre_tactic": mitre.get("tactic"),
        "mitre_technique_id": mitre.get("technique_id"),
        "mitre_technique_name": mitre.get("technique_name"),
    }, evidence)

def brute_force_001(df):
    alerts = []
    mask = (df['event'] == 'login') & (df['status'] == 'failed')
    if not mask.any(): return alerts
    
    df_sub = df[mask].copy()
    counts = df_sub.groupby(['user', 'ip'])['id'].rolling('10min').count()
    triggers = counts[counts >= 5]
    
    for (user, ip, ts), count in triggers.items():
        row_c = df_sub.loc[ts]
        if isinstance(row_c, pd.DataFrame): row = row_c[(row_c['user'] == user) & (row_c['ip'] == ip)].iloc[-1]
        else: row = row_c
        evidence = f"User {user} at IP {ip} had {int(count)} failed logins within 10 minutes (triggered at {ts})."
        alerts.append(_create_alert(row, ts, "brute_force_001", "Brute Force Login", "High", 85, evidence))
    return alerts

def priv_esc_001(df):
    alerts = []
    mask = df['event'].isin(['privilege_escalation', 'role_elevation'])
    if not mask.any(): return alerts
    
    for ts, row in df[mask].iterrows():
        evidence = f"User {row['user']} triggered explicit privilege escalation event '{row['event']}' at {ts}."
        alerts.append(_create_alert(row, ts, "priv_esc_001", "Privilege Escalation", "High", 90, evidence))
    return alerts

def recon_001(df):
    alerts = []
    mask = df['status'] == 'blocked'
    if not mask.any(): return alerts
    
    df_sub = df[mask].copy()
    counts = df_sub.groupby('user')['id'].rolling('30min').count()
    triggers = counts[counts >= 10]
    
    for (user, ts), count in triggers.items():
        row_c = df_sub.loc[ts]
        if isinstance(row_c, pd.DataFrame): row = row_c[row_c['user'] == user].iloc[-1]
        else: row = row_c
        evidence = f"User {user} had {int(count)} blocked access attempts within 30 minutes (triggered at {ts})."
        alerts.append(_create_alert(row, ts, "recon_001", "Reconnaissance / Access Denial Spray", "Medium", 60, evidence))
    return alerts

def off_hours_001(df):
    alerts = []
    mask = (df['event'] == 'login')
    if not mask.any(): return alerts
    
    df_sub = df[mask].copy()
    hours = df_sub.index.hour
    off_hours_mask = (hours >= 23) | (hours < 6)
    
    for ts, row in df_sub[off_hours_mask].iterrows():
        evidence = f"User {row['user']} logged in during off-hours ({ts.strftime('%H:%M:%S')}) from IP {row['ip']}."
        alerts.append(_create_alert(row, ts, "off_hours_001", "Off-Hours Access", "Medium", 40, evidence))
    return alerts

def impossible_travel_001(df):
    alerts = []
    df_sub = df.copy()
    df_sub['country'] = df_sub['ip'].apply(get_country)
    df_sub = df_sub[df_sub['country'] != 'Unknown']
    if df_sub.empty: return alerts
    
    df_sub = df_sub.sort_index()
    for user, user_df in df_sub.groupby('user'):
        if len(user_df) < 2:
            continue
        for i in range(1, len(user_df)):
            curr_row = user_df.iloc[i]
            curr_ts = user_df.index[i]
            start_time = curr_ts - pd.Timedelta(minutes=10)
            window = user_df[(user_df.index <= curr_ts) & (user_df.index >= start_time)]
            countries = window['country'].unique()
            if len(countries) >= 2:
                evidence = f"User {user} accessed from {len(countries)} different countries ({', '.join(countries)}) within 10 minutes (triggered at {curr_ts})."
                alerts.append(_create_alert(curr_row, curr_ts, "impossible_travel_001", "Impossible Travel", "High", 75, evidence))
    return alerts

def exfil_burst_001(df):
    alerts = []
    
    mask_export = df['event'] == 'export'
    if mask_export.any():
        df_export = df[mask_export].copy()
        counts = df_export.groupby('user')['id'].rolling('5min').count()
        triggers = counts[counts >= 100]
        for (user, ts), count in triggers.items():
            row_c = df_export.loc[ts]
            if isinstance(row_c, pd.DataFrame): row = row_c[row_c['user'] == user].iloc[-1]
            else: row = row_c
            evidence = f"User {user} exported {int(count)} records within 5 minutes at {ts}."
            alerts.append(_create_alert(row, ts, "exfil_burst_001", "Data Exfiltration Burst", "High", 80, evidence))
    
    df_sorted = df.copy()
    df_sorted['prev_status'] = df_sorted.groupby('user')['status'].shift(1)
    mask = (df_sorted['prev_status'] == 'blocked') & (df_sorted['event'] == 'export')
    
    for ts, row in df_sorted[mask].iterrows():
        evidence = f"User {row['user']} had an export event immediately following a blocked event at {ts}."
        alerts.append(_create_alert(row, ts, "exfil_burst_001", "Data Exfiltration Burst", "High", 80, evidence))
            
    return alerts

def dormant_account_001(df):
    alerts = []
    mask = df['event'] == 'login'
    if not mask.any(): return alerts
    
    df_sub = df[mask].copy()
    df_sub['ts_col'] = df_sub.index
    df_sub['time_diff'] = df_sub.groupby('user')['ts_col'].diff()
    
    triggers = df_sub[df_sub['time_diff'] > pd.Timedelta(days=30)]
    for ts, row in triggers.iterrows():
        days = row['time_diff'].days
        evidence = f"User {row['user']} logged in after being dormant for {days} days at {ts}."
        alerts.append(_create_alert(row, ts, "dormant_account_001", "Dormant/Terminated Account Access", "High", 70, evidence))
            
    return alerts

def run_all_rules(df):
    if df.empty:
        return []
    
    # ensure it's sorted by ts index if not already
    # df should already be prepared with ts as index
    # But just in case, if 'ts' is still a column:
    if 'ts' in df.columns:
        df = df.set_index('ts').sort_index()
    else:
        df = df.sort_index()
        
    all_alerts = []
    all_alerts.extend(brute_force_001(df))
    all_alerts.extend(priv_esc_001(df))
    all_alerts.extend(recon_001(df))
    all_alerts.extend(off_hours_001(df))
    all_alerts.extend(impossible_travel_001(df))
    all_alerts.extend(exfil_burst_001(df))
    all_alerts.extend(dormant_account_001(df))
    
    return all_alerts
