"""
MITRE ATT&CK Framework Mapping for Detection Rules.

Provides static mappings of rule IDs to MITRE ATT&CK tactics and techniques,
with safe fallbacks for unrecognized rule IDs.
"""

from typing import Dict, Any, Optional

DEFAULT_MITRE_MAPPING = {
    "tactic": "Unclassified",
    "technique_id": None,
    "technique_name": "Anomalous Behavior (No Direct ATT&CK Mapping)"
}

MITRE_RULE_MAPPINGS: Dict[str, Dict[str, Optional[str]]] = {
    "brute_force_001": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force"
    },
    "priv_esc_001": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation"
    },
    "recon_001": {
        "tactic": "Discovery",
        "technique_id": "T1087",
        "technique_name": "Account Discovery"
    },
    "off_hours_001": {
        "tactic": "Defense Evasion",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    "impossible_travel_001": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    "exfil_burst_001": {
        "tactic": "Exfiltration",
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service"
    },
    "dormant_account_001": {
        "tactic": "Persistence",
        "technique_id": "T1078.001",
        "technique_name": "Valid Accounts: Default Accounts"
    },
    "ml_anomaly_001": DEFAULT_MITRE_MAPPING
}


def get_mitre_info(rule_id: str) -> Dict[str, Any]:
    """
    Retrieve MITRE ATT&CK mapping for a given rule_id.
    Returns a safe default (Unclassified) for any unrecognized rule_id without raising exceptions.
    """
    if not rule_id:
        return DEFAULT_MITRE_MAPPING.copy()
    return MITRE_RULE_MAPPINGS.get(str(rule_id), DEFAULT_MITRE_MAPPING).copy()
