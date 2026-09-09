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
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

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
    mitre_techniques: Optional[str] = None
    
class IncidentListResponse(BaseModel):
    status: str
    total_incidents: int
    incidents: List[IncidentResponse]

class IncidentActionResponse(BaseModel):
    id: int
    action: str
    priority: str
    reason: str

class MitreTechniqueDetail(BaseModel):
    tactic: str
    technique_id: Optional[str] = None
    technique_name: str

class IncidentDetailResponse(BaseModel):
    status: str
    incident: IncidentResponse
    evidence_strings: List[str]
    rules_fired: List[str]
    ml_anomaly_score: Optional[float] = None
    contributing_alert_ids: List[int]
    recommended_actions: List[IncidentActionResponse]
    mitre_techniques: Optional[List[MitreTechniqueDetail]] = None

class MitreMatrixItem(BaseModel):
    tactic: str
    technique_id: Optional[str] = None
    technique_name: str
    incident_count: int
    count: int

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
    rows_inserted: Optional[int] = None
    rows_skipped: Optional[int] = None

class HealthResponse(BaseModel):
    status: str

class AlertsResponse(BaseModel):
    status: str
    alerts_generated: int
    alerts: List[AlertResponse]
