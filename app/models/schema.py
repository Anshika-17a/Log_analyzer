from sqlalchemy import Column, Integer, String, REAL, ForeignKey, CheckConstraint, Index, text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    ts = Column(String, nullable=False)
    user = Column(String, nullable=False)
    event = Column(String, nullable=False)
    resource = Column(String)
    ip = Column(String, nullable=False)
    status = Column(String)
    raw_line = Column(String)
    created_at = Column(String, server_default=text('CURRENT_TIMESTAMP'))

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    points = Column(Integer, server_default='0')
    ml_anomaly_score = Column(REAL)
    user = Column(String, nullable=False)
    ip = Column(String)
    evidence = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    log_id = Column(Integer, ForeignKey('logs.id'))
    incident_id = Column(Integer, ForeignKey('incidents.id'))
    created_at = Column(String, server_default=text('CURRENT_TIMESTAMP'))
    
    __table_args__ = (
        CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')"),
    )

class Incident(Base):
    __tablename__ = 'incidents'
    id = Column(Integer, primary_key=True)
    user = Column(String, nullable=False)
    ip = Column(String)
    risk_level = Column(String, nullable=False)
    score = Column(Integer, nullable=False)
    alert_count = Column(Integer, server_default='0')
    rules = Column(String) # comma-separated rule names
    first_event_time = Column(String)
    last_event_time = Column(String)
    status = Column(String, server_default='open')
    created_at = Column(String, server_default=text('CURRENT_TIMESTAMP'))
    updated_at = Column(String)

    __table_args__ = (
        CheckConstraint("risk_level IN ('Low', 'Medium', 'High', 'Critical')"),
        CheckConstraint("status IN ('open', 'reviewing', 'resolved', 'false_positive')"),
    )

class IncidentAction(Base):
    __tablename__ = 'incident_actions'
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey('incidents.id', ondelete='CASCADE'))
    action = Column(String, nullable=False)
    priority = Column(String, nullable=False)
    reason = Column(String)

    __table_args__ = (
        CheckConstraint("priority IN ('IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW')"),
    )

class EntityBaseline(Base):
    __tablename__ = 'entity_baseline'
    entity_id = Column(String, primary_key=True) # e.g. "user:alice" or "ip:1.2.3.4"
    avg_events_per_hour = Column(REAL, server_default='0')
    std_events_per_hour = Column(REAL, server_default='0')
    typical_login_hours = Column(String) # JSON array
    typical_resources = Column(String) # JSON array
    sample_size = Column(Integer, server_default='0')
    updated_at = Column(String)

class AuditLog(Base):
    __tablename__ = 'audit_log'
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey('incidents.id', ondelete='CASCADE'))
    change_type = Column(String, nullable=False)
    old_value = Column(String)
    new_value = Column(String)
    changed_by = Column(String, server_default='system')
    changed_at = Column(String, server_default=text('CURRENT_TIMESTAMP'))

# Indexes
Index('idx_logs_user_ts', Log.user, Log.ts)
Index('idx_logs_ip', Log.ip)
Index('idx_logs_event', Log.event)
Index('idx_alerts_user', Alert.user)
Index('idx_alerts_incident', Alert.incident_id)
Index('idx_alerts_rule', Alert.rule_id)
Index('idx_incidents_score', Incident.score.desc())
Index('idx_incidents_risk', Incident.risk_level)
Index('idx_incidents_status', Incident.status)
Index('idx_actions_incident', IncidentAction.incident_id)
Index('idx_audit_incident', AuditLog.incident_id)
