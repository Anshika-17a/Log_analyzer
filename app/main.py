import os
import hashlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import pandas as pd

from typing import List
from app.models.db import init_db, get_db
from app.models.schema import Log, Alert, Incident, IncidentAction, AuditLog, EntityBaseline
from app.models.api import (
    UploadResponse, HealthResponse, AlertsResponse, 
    IncidentListResponse, IncidentDetailResponse, 
    StatusUpdateRequest, NarrativeResponse,
    MitreMatrixItem
)
from app.ingestion.parser import parse_and_ingest_csv
from app.detection.rules import run_all_rules
from app.detection.baseline import compute_baselines
from app.detection.ml_anomaly import detect_anomalies
from app.detection.mitre_mapping import get_mitre_info
from app.correlation.grouping import group_and_correlate
from app.correlation.graph_builder import build_incident_graph
from app.reporting.report_generator import generate_incident_report_md, generate_summary_report_md, convert_markdown_to_pdf
from app.reporting.narrative import cluster_logs, generate_llm_narrative
from app.reporting.story_reconstruction import build_attack_story
from app.simulation import build_scenario_csv



@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Security Log Analyzer",
    description="A hybrid rule-based and ML-based security log analysis and correlation engine.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def to_dict(obj):
    d = obj.__dict__.copy()
    d.pop('_sa_instance_state', None)
    return d

templates = Jinja2Templates(directory="app/dashboard/templates")

@app.get("/", response_class=HTMLResponse, summary="Dashboard UI", include_in_schema=False)
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    total = db.query(Incident).count()
    critical = db.query(Incident).filter(Incident.risk_level == "Critical").count()
    high = db.query(Incident).filter(Incident.risk_level == "High").count()
    medium = db.query(Incident).filter(Incident.risk_level == "Medium").count()
    low = db.query(Incident).filter(Incident.risk_level == "Low").count()
    
    top_incidents = db.query(Incident).order_by(Incident.score.desc()).limit(20).all()
    
    counts = {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "counts": counts,
        "top_incidents": top_incidents,
        "last_refreshed": pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S UTC")
    })

@app.get("/health", response_model=HealthResponse, summary="Health Check")
def health_check():
    return {"status": "ok"}

@app.post("/api/logs/upload", response_model=UploadResponse, summary="Upload Logs", description="Uploads a CSV, JSON, JSONL or syslog file for ingestion.")
def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    filename = file.filename or "upload.csv"
    
    import io
    result = parse_and_ingest_csv(io.BytesIO(content), db, filename=filename)
    
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message", "Parse error"))
    
    processed = result.get("rows_inserted", 0)
    skipped   = result.get("rows_skipped", 0)
    fmt       = result.get("format", "csv")
    
    return {
        "status": "success",
        "processed": processed,
        "skipped": skipped,
        "rows_inserted": processed,
        "rows_skipped": skipped
    }


@app.get("/api/logs", summary="Get Ingested Logs", description="Paginated listing of ingested raw log records.")
def get_logs(page: int = 1, page_size: int = 20, db: Session = Depends(get_db)):
    offset = max(0, (page - 1) * page_size)
    total = db.query(Log).count()
    logs = db.query(Log).order_by(Log.id.asc()).offset(offset).limit(page_size).all()
    return {
        "status": "success",
        "total": total,
        "page": page,
        "page_size": page_size,
        "logs": [to_dict(l) for l in logs]
    }


@app.post("/api/system/reset", summary="Reset All System Data", description="Permanently clears all logs, alerts, incidents, actions, baselines, and audit entries to allow fresh log analysis.")
@app.post("/api/reset", include_in_schema=False)
@app.delete("/api/logs", include_in_schema=False)
def reset_system(db: Session = Depends(get_db)):
    try:
        # Delete children and related tables first (foreign key ordering)
        db.query(AuditLog).delete()
        db.query(IncidentAction).delete()
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.query(EntityBaseline).delete()
        db.query(Log).delete()
        db.commit()
        return {
            "status": "success",
            "message": "All logs, alerts, incidents, actions, baselines, and audit records have been cleared."
        }
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error while resetting data: {str(e)}")


@app.get("/api/alerts", response_model=AlertsResponse, summary="Generate Alerts", description="Runs the rule engine and ML baseline anomaly detection to generate alerts from the ingested logs.")
def get_alerts(db: Session = Depends(get_db)):
    logs = db.query(Log).all()
    if not logs:
        return {"status": "success", "alerts_generated": 0, "alerts": []}
        
    df = pd.DataFrame([l.__dict__ for l in logs])
    if '_sa_instance_state' in df.columns:
        df = df.drop(columns=['_sa_instance_state'])
    df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
    df = df.dropna(subset=['ts']).copy()
    
    compute_baselines(db, df)
    raw_alerts = run_all_rules(df)
    
    alert_mappings = []
    for alert_dict, evidence in raw_alerts:
        ad = alert_dict.copy()
        ad['evidence'] = evidence
        alert_mappings.append(ad)
        
    ml_alerts = detect_anomalies(db, df, alert_mappings)
    all_alerts = alert_mappings + ml_alerts
    for ad in all_alerts:
        if not ad.get("mitre_tactic"):
            m = get_mitre_info(ad.get("rule_id", ""))
            ad["mitre_tactic"] = m["tactic"]
            ad["mitre_technique_id"] = m["technique_id"]
            ad["mitre_technique_name"] = m["technique_name"]
        
    # Idempotent storage: remove prior unassigned alerts before persisting fresh detections
    db.query(Alert).filter(Alert.incident_id.is_(None)).delete()
    db.commit()

    if all_alerts:
        db.bulk_insert_mappings(Alert, all_alerts)
        db.commit()
        
    return {"status": "success", "alerts_generated": len(all_alerts), "alerts": all_alerts}

@app.get("/api/incidents", response_model=IncidentListResponse, summary="Correlate Incidents", description="Groups unassigned alerts into candidate incidents, calculates dynamic risk scores, and generates remediation recommendations.")
def get_incidents(db: Session = Depends(get_db)):
    incidents = group_and_correlate(db)
    incidents_sorted = sorted(incidents, key=lambda x: x.score, reverse=True)
    return {"status": "success", "total_incidents": len(incidents_sorted), "incidents": [to_dict(i) for i in incidents_sorted]}

@app.get("/api/incidents/{id}", response_model=IncidentDetailResponse, summary="Get Incident Details", description="Retrieves the detailed view of a specific incident, including evidence strings, fired rules, and recommended actions.")
def get_incident_detail(id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    alerts = db.query(Alert).filter(Alert.incident_id == id).all()
    actions = db.query(IncidentAction).filter(IncidentAction.incident_id == id).all()
    
    evidence_strings = [a.evidence for a in alerts]
    rules_fired = list(set([a.rule_name for a in alerts]))
    ml_anomaly_score = max([a.ml_anomaly_score for a in alerts if a.ml_anomaly_score is not None] or [None])
    contributing_alert_ids = [a.id for a in alerts]
    
    distinct_techniques = []
    seen_keys = set()
    for a in alerts:
        tactic = a.mitre_tactic
        tech_id = a.mitre_technique_id
        tech_name = a.mitre_technique_name
        if not tactic:
            m = get_mitre_info(a.rule_id)
            tactic = m["tactic"]
            tech_id = m["technique_id"]
            tech_name = m["technique_name"]
        key = (tactic, tech_id, tech_name)
        if key not in seen_keys:
            seen_keys.add(key)
            distinct_techniques.append({
                "tactic": tactic,
                "technique_id": tech_id,
                "technique_name": tech_name
            })
    
    return {
        "status": "success",
        "incident": to_dict(incident),
        "evidence_strings": evidence_strings,
        "rules_fired": rules_fired,
        "ml_anomaly_score": ml_anomaly_score,
        "contributing_alert_ids": contributing_alert_ids,
        "recommended_actions": [to_dict(act) for act in actions],
        "mitre_techniques": distinct_techniques
    }

@app.get("/api/incidents/{id}/graph", summary="Get Incident Attack Graph", description="Returns an entity-relationship graph linking users, IPs, triggered rules, MITRE ATT&CK techniques, and containment actions.")
def get_incident_graph(id: int, db: Session = Depends(get_db)):
    graph = build_incident_graph(id, db)
    if "error" in graph:
        raise HTTPException(status_code=404, detail=graph["error"])
    return graph

@app.get("/api/incidents/{id}/story", summary="Get Incident Attack Story", description="Returns a chronological, plain-English kill-chain narrative reconstructed from MITRE tactics, alert evidence, and incident metadata.")
def get_incident_story(id: int, db: Session = Depends(get_db)):
    story = build_attack_story(id, db)
    if "error" in story:
        raise HTTPException(status_code=404, detail=story["error"])
    return story

@app.get("/api/incidents/{id}/narrative", response_model=NarrativeResponse, summary="Generate LLM Narrative", description="Clusters incident logs via Drain3 and prompts an LLM for an executive summary.")
def get_incident_narrative(id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    query = db.query(Log).filter(Log.user == incident.user)
    if incident.first_event_time and incident.last_event_time:
        query = query.filter(Log.ts >= incident.first_event_time, Log.ts <= incident.last_event_time)
    logs = query.all()
    if not logs:
        logs = db.query(Log).filter(Log.user == incident.user).limit(50).all()
        
    raw_lines = [l.raw_line if l.raw_line else f"{l.ts} {l.action} user={l.user} src_ip={l.src_ip} status={l.status}" for l in logs]
    
    if not raw_lines:
        alerts = db.query(Alert).filter(Alert.incident_id == id).all()
        raw_lines = [a.evidence for a in alerts if a.evidence]
        
    clustered = cluster_logs(raw_lines)
    
    context = {
        "user": incident.user,
        "risk_level": incident.risk_level,
        "score": incident.score,
        "rules": incident.rules
    }
    
    narrative = generate_llm_narrative(context, clustered)
    
    return {
        "status": "success",
        "incident_id": id,
        "narrative": narrative
    }


@app.get("/api/mitre/matrix", response_model=List[MitreMatrixItem], summary="MITRE ATT&CK Matrix", description="Returns a summary across all current incidents: for every technique that has appeared, how many incidents it appeared in.")
def get_mitre_matrix(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    if not incidents:
        return []

    alerts = db.query(Alert).filter(Alert.incident_id.isnot(None)).all()
    inc_alerts = {}
    for a in alerts:
        inc_alerts.setdefault(a.incident_id, []).append(a)

    counts = {}
    for incident in incidents:
        technique_set = set()
        for a in inc_alerts.get(incident.id, []):
            tactic = a.mitre_tactic
            tech_id = a.mitre_technique_id
            tech_name = a.mitre_technique_name
            if not tactic:
                m = get_mitre_info(a.rule_id)
                tactic = m["tactic"]
                tech_id = m["technique_id"]
                tech_name = m["technique_name"]
            technique_set.add((tactic, tech_id, tech_name))
        
        for key in technique_set:
            counts[key] = counts.get(key, 0) + 1

    matrix = [
        {
            "tactic": tactic,
            "technique_id": tech_id,
            "technique_name": tech_name,
            "incident_count": cnt,
            "count": cnt
        }
        for (tactic, tech_id, tech_name), cnt in counts.items()
    ]
    matrix.sort(key=lambda x: (-x["incident_count"], x["technique_name"]))
    return matrix

@app.put("/api/incidents/{id}/status", summary="Update Incident Status", description="Atomically updates the status of an incident and records an AuditLog entry.")
def update_incident_status(id: int, request: StatusUpdateRequest, db: Session = Depends(get_db)):
    if request.status not in ("open", "reviewing", "resolved", "false_positive"):
        raise HTTPException(status_code=422, detail="Invalid status")
        
    incident = db.query(Incident).filter(Incident.id == id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    old_status = incident.status
    
    try:
        incident.status = request.status
        incident.updated_at = pd.Timestamp.now(tz="UTC").isoformat()
        
        audit_log = AuditLog(
            incident_id=id,
            change_type="status_update",
            old_value=old_status,
            new_value=request.status,
            changed_by=getattr(request, "changed_by", "system")
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database transaction failed")
        
    return {"status": "success", "message": "Incident status updated successfully"}

@app.post("/api/simulate/{scenario}", summary="Simulate Live Attack Scenario", description="Injects real raw telemetry logs for a benchmark scenario (apt29, insider, benign), runs full ingestion, baselines, detection, and correlation live.")
def simulate_scenario(scenario: str, db: Session = Depends(get_db)):
    if scenario not in ("apt29", "insider", "benign"):
        raise HTTPException(status_code=400, detail="Invalid scenario. Choose: apt29, insider, benign")
    
    # 1. Clean slate
    reset_system(db)
    
    # 2. Build authentic raw telemetry CSV
    buf, filename, sample_stream = build_scenario_csv(scenario)
    
    # 3. Ingest raw CSV through normal pipeline parser
    result = parse_and_ingest_csv(buf, db, filename=filename)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message", "Ingestion error"))
        
    # 4. Compute entity baselines, evaluate all Sigma/MITRE rules, and run ML anomaly detection
    logs = db.query(Log).all()
    all_alerts = []
    if logs:
        df = pd.DataFrame([l.__dict__ for l in logs])
        if '_sa_instance_state' in df.columns:
            df = df.drop(columns=['_sa_instance_state'])
        df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
        df = df.dropna(subset=['ts']).copy()
        
        compute_baselines(db, df)
        raw_alerts = run_all_rules(df)
        
        alert_mappings = []
        for alert_dict, evidence in raw_alerts:
            ad = alert_dict.copy()
            ad['evidence'] = evidence
            alert_mappings.append(ad)
            
        ml_alerts = detect_anomalies(db, df, alert_mappings)
        all_alerts = alert_mappings + ml_alerts
        for ad in all_alerts:
            if not ad.get("mitre_tactic"):
                m = get_mitre_info(ad.get("rule_id", ""))
                ad["mitre_tactic"] = m["tactic"]
                ad["mitre_technique_id"] = m["technique_id"]
                ad["mitre_technique_name"] = m["technique_name"]
                
        db.query(Alert).filter(Alert.incident_id.is_(None)).delete()
        db.commit()
        if all_alerts:
            db.bulk_insert_mappings(Alert, all_alerts)
            db.commit()
            
    # 5. Correlate alerts into multi-stage incidents with dynamic risk scoring
    incidents = group_and_correlate(db)
    
    top_incident_id = None
    if incidents:
        sorted_incidents = sorted(incidents, key=lambda x: getattr(x, 'score', 0) or 0, reverse=True)
        top_incident_id = sorted_incidents[0].id

    return {
        "status": "success",
        "scenario": scenario,
        "filename": filename,
        "rows_ingested": result.get("rows_inserted", 0),
        "alerts_count": len(all_alerts),
        "incidents_count": len(incidents),
        "top_incident_id": top_incident_id,
        "sample_stream": sample_stream
    }


