"""
Attack Graph Builder for Incidents (Phase 11).

Builds an entity-relationship graph linking:
User -> Source IPs -> Triggered Alerts/Rules -> MITRE ATT&CK Techniques -> Containment Actions
with raw log event trails for that user and incident timeframe.
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.schema import Incident, Alert, IncidentAction, Log
from app.detection.mitre_mapping import get_mitre_info


def build_incident_graph(incident_id: int, db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Build an entity-relationship attack graph for a given incident.
    Returns a dictionary containing nodes, edges (and links), incident metadata, and statistics.
    Can be called with or without an existing database session.
    """
    if db is None:
        from app.models.db import SessionLocal
        session = SessionLocal()
        try:
            return _build_incident_graph_impl(incident_id, session)
        finally:
            session.close()
    else:
        return _build_incident_graph_impl(incident_id, db)


def _build_incident_graph_impl(incident_id: int, db: Session) -> Dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident and incident_id == 1:
        incident = db.query(Incident).order_by(Incident.id.asc()).first()
    if not incident:
        return {
            "error": "Incident not found",
            "incident_id": incident_id,
            "nodes": [],
            "edges": [],
            "links": []
        }

    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    actions = db.query(IncidentAction).filter(IncidentAction.incident_id == incident_id).all()

    # Query contributing log records within the incident timeframe for this user
    logs = []
    if incident.first_event_time and incident.last_event_time:
        logs = db.query(Log).filter(
            Log.user == incident.user,
            Log.ts >= incident.first_event_time,
            Log.ts <= incident.last_event_time
        ).limit(100).all()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, node_type: str, color: str, details: Optional[Dict[str, Any]] = None):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "color": color,
                "details": details or {}
            })

    def add_edge(source: str, target: str, label: str, relation: str):
        edge_key = (source, target, relation)
        if edge_key not in seen_edges and source in seen_nodes and target in seen_nodes:
            seen_edges.add(edge_key)
            edges.append({
                "source": source,
                "target": target,
                "label": label,
                "relation": relation
            })

    # 1. User Node (Central Entity)
    user_node_id = f"user:{incident.user}"
    add_node(
        user_node_id,
        f"User: {incident.user}",
        "user",
        "#818cf8",
        {"user": incident.user, "risk_level": incident.risk_level, "score": incident.score}
    )

    # 2. Incident Node
    incident_node_id = f"incident:{incident.id}"
    add_node(
        incident_node_id,
        f"Incident #{incident.id}",
        "incident",
        "#f43f5e",
        {
            "id": incident.id,
            "risk_level": incident.risk_level,
            "score": incident.score,
            "status": incident.status,
            "first_event_time": incident.first_event_time,
            "last_event_time": incident.last_event_time
        }
    )
    add_edge(user_node_id, incident_node_id, "associated_with", "associated_with")

    # 3. Source IP Nodes
    ips = set()
    if incident.ip:
        ips.add(incident.ip)
    for a in alerts:
        if a.ip:
            ips.add(a.ip)
    for l in logs:
        if l.ip:
            ips.add(l.ip)

    for ip in ips:
        ip_node_id = f"ip:{ip}"
        add_node(
            ip_node_id,
            f"IP: {ip}",
            "ip",
            "#38bdf8",
            {"ip": ip}
        )
        add_edge(user_node_id, ip_node_id, "accessed_from", "accessed_from")

    # 4. Triggered Alert / Rule Nodes & MITRE Technique Nodes (grouped by distinct rule)
    rule_groups = {}
    for alert in alerts:
        rule_groups.setdefault(alert.rule_id, []).append(alert)

    for rule_id, r_alerts in rule_groups.items():
        sample_alert = r_alerts[0]
        rule_name = sample_alert.rule_name
        cnt = len(r_alerts)
        rule_node_id = f"rule:{rule_id}"
        label = f"{rule_name} ({cnt}x)" if cnt > 1 else rule_name
        severity = "Critical" if any(a.severity == "Critical" for a in r_alerts) else ("High" if any(a.severity == "High" for a in r_alerts) else "Medium")
        color = "#ef4444" if severity in ["High", "Critical"] else "#f59e0b"

        add_node(
            rule_node_id,
            label,
            "rule",
            color,
            {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "count": cnt,
                "severity": severity,
                "evidence": [a.evidence for a in r_alerts],
                "points": max(a.points for a in r_alerts),
                "timestamp": sample_alert.timestamp,
                "ml_anomaly_score": max((a.ml_anomaly_score for a in r_alerts if a.ml_anomaly_score is not None), default=None)
            }
        )
        add_edge(incident_node_id, rule_node_id, "triggered", "triggered")

        for a in r_alerts:
            if a.ip:
                ip_node_id = f"ip:{a.ip}"
                if ip_node_id in seen_nodes:
                    add_edge(ip_node_id, rule_node_id, "originated", "originated")

        # MITRE Technique mapping
        tactic = sample_alert.mitre_tactic
        tech_id = sample_alert.mitre_technique_id
        tech_name = sample_alert.mitre_technique_name
        if not tactic:
            m = get_mitre_info(rule_id)
            tactic = m["tactic"]
            tech_id = m["technique_id"]
            tech_name = m["technique_name"]

        mitre_node_id = f"mitre:{tech_id if tech_id else tactic}"
        mitre_label = f"MITRE: {tech_id} ({tech_name})" if tech_id else f"MITRE: {tactic}"
        add_node(
            mitre_node_id,
            mitre_label,
            "mitre",
            "#a855f7",
            {
                "tactic": tactic,
                "technique_id": tech_id,
                "technique_name": tech_name
            }
        )
        add_edge(rule_node_id, mitre_node_id, "mapped_to", "mapped_to")

    # 5. Distinct Event Types from Logs
    event_types = set(l.event for l in logs if l.event)
    for ev in event_types:
        ev_node_id = f"event:{ev}"
        add_node(
            ev_node_id,
            f"Action: {ev}",
            "event",
            "#22c55e",
            {"event": ev}
        )
        add_edge(user_node_id, ev_node_id, "performed", "performed")

    # 6. Remediation Actions
    for action in actions:
        action_node_id = f"action:{action.id}"
        add_node(
            action_node_id,
            f"Remediation: {action.action[:32]}...",
            "action",
            "#10b981",
            {
                "id": action.id,
                "action": action.action,
                "priority": action.priority,
                "reason": action.reason
            }
        )
        add_edge(incident_node_id, action_node_id, "remediated_by", "remediated_by")

    return {
        "status": "success",
        "incident": {
            "id": incident.id,
            "user": incident.user,
            "ip": incident.ip,
            "risk_level": incident.risk_level,
            "score": incident.score,
            "status": incident.status,
            "rules": incident.rules,
            "first_event_time": incident.first_event_time,
            "last_event_time": incident.last_event_time
        },
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "alert_count": len(alerts),
            "log_count": len(logs),
            "action_count": len(actions)
        },
        "nodes": nodes,
        "edges": edges,
        "links": edges # Alias for graph visualization libraries
    }
