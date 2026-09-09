import re

def calculate_score(alert_group):
    rule_alerts = [a for a in alert_group if a.rule_id != 'ml_anomaly_001']
    ml_alerts = [a for a in alert_group if a.rule_id == 'ml_anomaly_001']
    
    rule_component = max([a.points for a in rule_alerts]) if rule_alerts else 0
    
    alert_count = len(alert_group)
    frequency_bonus = min(alert_count * 2, 20)
    
    ml_component = 0
    deviation_component = 0
    
    if ml_alerts:
        max_anomaly = max([a.ml_anomaly_score for a in ml_alerts if a.ml_anomaly_score is not None] or [0])
        ml_component = max_anomaly * 30
        
        max_dev = 0
        for m in ml_alerts:
            match = re.search(r'deviation_from_user_baseline=([\d\.]+)', m.evidence)
            if match:
                dev = float(match.group(1))
                if dev > max_dev:
                    max_dev = dev
        deviation_component = min(max_dev * 5, 15)
        
    dynamic_score = rule_component + frequency_bonus + ml_component + deviation_component
    
    if dynamic_score >= 85:
        risk_level = "Critical"
    elif dynamic_score >= 65:
        risk_level = "High"
    elif dynamic_score >= 45:
        risk_level = "Medium"
    else:
        risk_level = "Low"
        
    return int(dynamic_score), risk_level
