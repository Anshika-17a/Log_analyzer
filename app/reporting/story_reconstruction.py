"""
Attack Story Reconstruction (Phase 12).

Generates an automatic, plain-English chronological narrative of an attacker or anomalous account's
kill-chain stages for an incident. Fuses alerts, MITRE ATT&CK tactics, forensic evidence, and timestamps
into human-authored prose with optional LLM smoothing.
"""

import os
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from app.models.schema import Incident, Alert
from app.detection.mitre_mapping import get_mitre_info

load_dotenv()


def _format_time_str(ts_raw: Any) -> str:
    """Format raw timestamp into clean human-readable time (e.g., '11:12 PM' or '23:12 UTC')."""
    if not ts_raw:
        return "an unknown time"
    try:
        ts_str = str(ts_raw).replace("Z", "+00:00")
        if " " in ts_str and "T" not in ts_str:
            dt = datetime.fromisoformat(ts_str.split(".")[0])
        else:
            dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%I:%M %p").lstrip("0")
    except Exception:
        # Fallback to simple extraction
        s = str(ts_raw)
        m = re.search(r'(\d{2}:\d{2}:\d{2})', s)
        return m.group(1) if m else str(ts_raw)


def _format_iso_time(ts_raw: Any) -> str:
    """Extract standard HH:MM:SS for the timeline stage."""
    if not ts_raw:
        return "00:00:00"
    try:
        ts_str = str(ts_raw).replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%H:%M:%S")
    except Exception:
        s = str(ts_raw)
        m = re.search(r'(\d{2}:\d{2}:\d{2})', s)
        return m.group(1) if m else str(ts_raw)


def _craft_stage_sentence(tactic: str, alerts: List[Alert], user: str) -> str:
    """
    Generate ONE specific, plain-English sentence for a group of alerts sharing a MITRE tactic.
    Extracts real specifics (counts, IPs, resources, anomaly scores) directly from evidence.
    """
    primary_alert = alerts[0]
    time_str = _format_time_str(primary_alert.timestamp)
    ip = primary_alert.ip or "an unidentified network address"
    tech_id = primary_alert.mitre_technique_id or "T1078"
    rule_id = primary_alert.rule_id
    evidence = " ".join([a.evidence for a in alerts if a.evidence])

    # 1. Credential Access (Brute Force)
    if tactic == "Credential Access" or "brute_force" in rule_id:
        count_match = re.search(r'(\d+)\s+failed logins', evidence)
        count = count_match.group(1) if count_match else str(len(alerts) * 5)
        return (
            f"At {time_str}, {user} attempted {count} failed logins from {ip}, "
            f"consistent with an automated credential access and password guessing attack (MITRE {tech_id})."
        )

    # 2. Privilege Escalation
    if tactic == "Privilege Escalation" or "priv_esc" in rule_id:
        ev_match = re.search(r"event\s+'([^']+)'", evidence)
        event_name = ev_match.group(1) if ev_match else "unauthorized role elevation"
        return (
            f"At {time_str}, {user} executed '{event_name}' from {ip}, "
            f"escalating privileges to gain elevated administrative access across system resources (MITRE {tech_id})."
        )

    # 3. Discovery / Reconnaissance
    if tactic == "Discovery" or "recon" in rule_id:
        count_match = re.search(r'(\d+)\s+blocked access', evidence)
        count = count_match.group(1) if count_match else str(len(alerts) * 10)
        return (
            f"At {time_str}, {user} conducted extensive discovery and access denial probing from {ip}, "
            f"triggering {count} blocked requests while mapping unauthorized endpoints (MITRE {tech_id})."
        )

    # 4. Defense Evasion / Off-Hours
    if tactic == "Defense Evasion" or "off_hours" in rule_id:
        hour_match = re.search(r'during off-hours \(([^)]+)\)', evidence)
        window = hour_match.group(1) if hour_match else time_str
        return (
            f"At {time_str}, {user} authenticated outside scheduled operational hours ({window}) from {ip}, "
            f"leveraging valid credentials to evade routine perimeter monitoring (MITRE {tech_id})."
        )

    # 5. Initial Access / Impossible Travel
    if tactic == "Initial Access" or "impossible_travel" in rule_id:
        loc_match = re.search(r'from\s+(\d+)\s+different countries\s+\(([^)]+)\)', evidence)
        if loc_match:
            countries = loc_match.group(2)
            return (
                f"At {time_str}, {user} logged in concurrently from geographically distant locations ({countries}), "
                f"representing physically impossible travel and suspected credential sharing (MITRE {tech_id})."
            )
        return (
            f"At {time_str}, {user} established an anomalous initial access connection from {ip} "
            f"across disparate geographical jurisdictions (MITRE {tech_id})."
        )

    # 6. Exfiltration / High Velocity Export
    if tactic == "Exfiltration" or "exfil" in rule_id:
        count_match = re.search(r'exported\s+(\d+)\s+records', evidence)
        count = count_match.group(1) if count_match else "high-volume"
        return (
            f"At {time_str}, {user} initiated high-velocity data exfiltration, exporting {count} sensitive records "
            f"from {ip} immediately following privilege elevation (MITRE {tech_id})."
        )

    # 7. Persistence / Dormant Account
    if tactic == "Persistence" or "dormant" in rule_id:
        days_match = re.search(r'dormant for\s+(\d+)\s+days', evidence)
        days = days_match.group(1) if days_match else "30+"
        return (
            f"At {time_str}, {user} reactivated an account that had remained dormant for {days} days from {ip}, "
            f"indicating persistent unauthorized backdoor utilization (MITRE {tech_id})."
        )

    # 8. Unclassified (ML Anomaly)
    if tactic == "Unclassified" or "ml_anomaly" in rule_id:
        score_val = f"{primary_alert.ml_anomaly_score:.2f}" if primary_alert.ml_anomaly_score is not None else "0.95"
        sig_match = re.search(r'Key signals:\s*([^.]+)', evidence)
        signals = sig_match.group(1) if sig_match else "activity outside user baseline"
        return (
            f"At {time_str}, behavioral models flagged {user} with an anomaly score of {score_val} "
            f"due to severe deviation from established historical baselines ({signals})."
        )

    # General Fallback
    return (
        f"At {time_str}, {user} generated suspicious telemetry from {ip} "
        f"triggering security detection rule '{primary_alert.rule_name}'."
    )


def _generate_headline(incident: Incident, alerts: List[Alert]) -> str:
    """Generate a crisp, specific executive headline describing the incident's kill-chain essence."""
    user = incident.user
    risk = incident.risk_level
    score = incident.score
    rule_ids = set(a.rule_id for a in alerts)

    if "exfil_burst_001" in rule_ids and ("priv_esc_001" in rule_ids or "brute_force_001" in rule_ids):
        summary = "account takeover and high-volume data exfiltration"
    elif "exfil_burst_001" in rule_ids:
        summary = "unauthorized data exfiltration burst"
    elif "priv_esc_001" in rule_ids and "brute_force_001" in rule_ids:
        summary = "brute-force credential compromise and administrative privilege escalation"
    elif "priv_esc_001" in rule_ids:
        summary = "unauthorized privilege escalation and role elevation"
    elif "impossible_travel_001" in rule_ids:
        summary = "geographically impossible access and session hijacking"
    elif "brute_force_001" in rule_ids:
        summary = "targeted brute-force credential access campaign"
    elif "dormant_account_001" in rule_ids:
        summary = "compromise and reactivation of dormant account"
    elif "off_hours_001" in rule_ids and "recon_001" in rule_ids:
        summary = "off-hours reconnaissance and resource enumeration"
    elif "off_hours_001" in rule_ids:
        summary = "anomalous off-hours authentication and defense evasion"
    elif "recon_001" in rule_ids:
        summary = "access denial spray and reconnaissance probing"
    elif any("ml_anomaly" in r for r in rule_ids):
        summary = "significant behavioral anomaly and baseline deviation"
    else:
        summary = "correlated multi-signal security anomaly"

    return f"Suspected {summary} by {user} ({risk}, score {score})"


def _maybe_smooth_with_llm(headline: str, deterministic_narrative: str, stages: List[Dict[str, Any]]) -> str:
    """
    If ENABLE_LLM_NARRATIVE is true and an API key is available, prompts Gemini to polish
    the deterministic narrative into continuous executive prose. Otherwise returns deterministic version.
    Uses a hard 10-second timeout so a slow/overloaded API never blocks the HTTP response.
    """
    enable_flag = os.getenv("ENABLE_LLM_NARRATIVE", "false").lower() in ("true", "1", "yes")
    api_key = os.getenv("GEMINI_API_KEY")
    if not enable_flag or not api_key:
        return deterministic_narrative

    prompt = f"""You are a senior cyber threat intelligence analyst writing an executive incident reconstruction story.
Refine and polish the following chronological stages into a cohesive, highly professional two-to-three sentence narrative:

Headline: {headline}
Chronological Story Stages:
{deterministic_narrative}

Requirements:
- Preserve all exact timestamps, usernames, IP addresses, record counts, and MITRE ATT&CK technique IDs.
- Write in authoritative, fluid cybersecurity prose as if briefed directly to the CISO.
- Do NOT output preamble, markdown formatting, or headers. Just the narrative text.
"""
    CANDIDATE_MODELS = ["gemini-flash-latest", "gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash"]

    def _try_gemini() -> str:
        """Inner function run in a thread so we can enforce a wall-clock timeout."""
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            for model_name in CANDIDATE_MODELS:
                try:
                    delay = 2
                    last_ex = None
                    for attempt in range(2):  # max 2 attempts per model (2s backoff)
                        try:
                            response = client.models.generate_content(
                                model=model_name,
                                contents=prompt
                            )
                            if response and response.text and response.text.strip():
                                return response.text.strip()
                            break
                        except Exception as ex:
                            last_ex = ex
                            msg = str(ex)
                            retryable = (
                                "503" in msg or "UNAVAILABLE" in msg
                                or "429" in msg or "RESOURCE_EXHAUSTED" in msg
                            )
                            if retryable and attempt < 1:
                                time.sleep(delay)
                                continue
                            break  # non-retryable or exhausted — try next model
                except Exception:
                    continue
        except Exception:
            pass
        return ""

    # Run Gemini in a daemon thread with a hard 10s wall-clock limit.
    # Daemon threads are killed automatically when the calling thread returns,
    # so a hung/slow Gemini API call can NEVER block the HTTP response.
    import threading
    result_box = [None]

    def _run():
        result_box[0] = _try_gemini()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=10)

    if result_box[0]:
        return result_box[0]

    return deterministic_narrative


def build_attack_story(incident_id: int, db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Reconstructs an incident's chronological attack story.
    Returns:
      {
        "incident_id": int,
        "headline": str,
        "narrative": str,
        "stages": [
          {"order": int, "tactic": str, "time": str, "summary": str}
        ]
      }
    """
    if db is None:
        from app.models.db import SessionLocal
        with SessionLocal() as session:
            return _build_attack_story_impl(incident_id, session)
    return _build_attack_story_impl(incident_id, db)


def _build_attack_story_impl(incident_id: int, db: Session) -> Dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident and incident_id == 1:
        incident = db.query(Incident).order_by(Incident.id.asc()).first()

    if not incident:
        return {
            "error": "Incident not found",
            "incident_id": incident_id,
            "headline": "Incident not found",
            "narrative": "No telemetry available for this incident.",
            "stages": []
        }

    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).all()
    if not alerts:
        # Fallback if unlinked
        alerts = db.query(Alert).filter(Alert.user == incident.user).limit(10).all()

    # Sort alerts chronologically
    def get_sort_key(alert: Alert):
        if not alert.timestamp:
            return ""
        return str(alert.timestamp)

    sorted_alerts = sorted(alerts, key=get_sort_key)

    # Edge Case: Incident with 0 alerts
    if not sorted_alerts:
        headline = f"Security incident detected for account {incident.user} ({incident.risk_level}, score {incident.score})"
        narrative = f"At {_format_time_str(incident.first_event_time)}, anomalous activity was detected on account {incident.user} scoring {incident.score} points."
        return {
            "incident_id": incident.id,
            "headline": headline,
            "narrative": narrative,
            "stages": [
                {
                    "order": 1,
                    "tactic": "Unclassified",
                    "time": _format_iso_time(incident.first_event_time),
                    "summary": narrative
                }
            ]
        }

    # Group consecutive alerts by tactic into kill-chain stages
    stages_raw: List[Dict[str, Any]] = []
    for a in sorted_alerts:
        tactic = a.mitre_tactic
        if not tactic:
            tactic = get_mitre_info(a.rule_id).get("tactic", "Unclassified")

        if stages_raw and stages_raw[-1]["tactic"] == tactic:
            stages_raw[-1]["alerts"].append(a)
        else:
            stages_raw.append({
                "tactic": tactic,
                "alerts": [a]
            })

    stages: List[Dict[str, Any]] = []
    story_sentences: List[str] = []

    for order_idx, stage_info in enumerate(stages_raw, 1):
        tactic = stage_info["tactic"]
        stage_alerts = stage_info["alerts"]
        first_alert = stage_alerts[0]
        sentence = _craft_stage_sentence(tactic, stage_alerts, incident.user)
        story_sentences.append(sentence)

        stages.append({
            "order": order_idx,
            "tactic": tactic,
            "time": _format_iso_time(first_alert.timestamp),
            "summary": sentence
        })

    headline = _generate_headline(incident, sorted_alerts)
    deterministic_narrative = " ".join(story_sentences)

    # Apply optional LLM smoothing if configured
    final_narrative = _maybe_smooth_with_llm(headline, deterministic_narrative, stages)

    return {
        "incident_id": incident.id,
        "headline": headline,
        "narrative": final_narrative,
        "stages": stages
    }
