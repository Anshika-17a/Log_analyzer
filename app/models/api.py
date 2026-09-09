from pydantic import BaseModel
from typing import List, Optional

class AlertResponse(BaseModel):
    id: Optional[int] = None
    rule_id: str
    rule_name: str
    severity: str
    points: int
    ml_anomaly_score: Optional[float] = None
    user: str
    ip: Optional[str] = None
    evidence: str
    timestamp: str
    log_id: Optional[int] = None
    incident_id: Optional[int] = None
    created_at: Optional[str] = None

class IncidentResponse(BaseModel):
    id: int
    user: str
    ip: Optional[str] = None
    risk_level: str
    score: int
    alert_count: int
    rules: str
    first_event_time: str
    last_event_time: str
    status: str
    created_at: str
    updated_at: Optional[str] = None
    
class IncidentListResponse(BaseModel):
    status: str
    total_incidents: int
    incidents: List[IncidentResponse]

class IncidentActionResponse(BaseModel):
    id: int
    action: str
    priority: str
    reason: str

class IncidentDetailResponse(BaseModel):
    status: str
    incident: IncidentResponse
    evidence_strings: List[str]
    rules_fired: List[str]
    ml_anomaly_score: Optional[float] = None
    contributing_alert_ids: List[int]
    recommended_actions: List[IncidentActionResponse]

class StatusUpdateRequest(BaseModel):
    status: str

class NarrativeResponse(BaseModel):
    status: str
    incident_id: int
    narrative: str
    changed_by: Optional[str] = "system"

class UploadResponse(BaseModel):
    status: str
    processed: int
    skipped: int

class HealthResponse(BaseModel):
    status: str

class AlertsResponse(BaseModel):
    status: str
    alerts_generated: int
    alerts: List[AlertResponse]
