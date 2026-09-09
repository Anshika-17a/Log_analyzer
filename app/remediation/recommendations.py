from app.models.schema import IncidentAction

ACTION_MAPPINGS = {
    "brute_force_001": {
        "action": "Force password reset and enable MFA for this account",
        "priority": "IMMEDIATE"
    },
    "priv_esc_001": {
        "action": "Review and revoke elevated role if unauthorized; notify account owner's manager",
        "priority": "IMMEDIATE"
    },
    "recon_001": {
        "action": "Temporarily rate-limit or block the source IP; review access control lists",
        "priority": "HIGH"
    },
    "off_hours_001": {
        "action": "Verify with the user whether this login was expected; consider requiring MFA re-auth",
        "priority": "MEDIUM"
    },
    "impossible_travel_001": {
        "action": "Lock the account pending user verification; check for compromised credentials",
        "priority": "IMMEDIATE"
    },
    "exfil_burst_001": {
        "action": "Suspend export permissions immediately and audit exported data",
        "priority": "IMMEDIATE"
    },
    "dormant_account_001": {
        "action": "Disable the account and investigate how it was accessed",
        "priority": "HIGH"
    },
    "ml_anomaly_001": {
        "action": "Manually review this entity's recent activity against its behavioral baseline",
        "priority": "MEDIUM"
    }
}

def generate_recommendations(incident_id: int, alerts: list) -> list:
    actions = []
    processed_rules = set()
    
    for alert in alerts:
        rule_id = alert.rule_id
        if rule_id in processed_rules:
            continue
            
        processed_rules.add(rule_id)
        
        mapping = ACTION_MAPPINGS.get(rule_id)
        if not mapping:
            continue
            
        reason = f"Triggered by {alert.rule_name}. Evidence: {alert.evidence}"
        
        actions.append(IncidentAction(
            incident_id=incident_id,
            action=mapping["action"],
            priority=mapping["priority"],
            reason=reason
        ))
        
    return actions
