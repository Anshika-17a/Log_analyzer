from app.models.db import SessionLocal
from app.models.schema import Incident
from app.reporting.story_reconstruction import build_attack_story

with SessionLocal() as db:
    top_inc = db.query(Incident).order_by(Incident.score.desc()).first()
    if top_inc:
        story = build_attack_story(top_inc.id, db)
        print("=== CRITICAL INCIDENT STORY ===")
        print("ID:", story["incident_id"])
        print("Headline:", story["headline"])
        print("Narrative:\n", story["narrative"])
        print("Stages:", len(story["stages"]))
        for s in story["stages"]:
            print(f"  [{s['order']}] {s['time']} - {s['tactic']}: {s['summary']}")

    one_alert_inc = db.query(Incident).filter(Incident.alert_count == 1).first()
    if one_alert_inc:
        story1 = build_attack_story(one_alert_inc.id, db)
        print("\n=== 1-ALERT INCIDENT STORY ===")
        print("ID:", story1["incident_id"])
        print("Headline:", story1["headline"])
        print("Narrative:\n", story1["narrative"])
        print("Stages:", len(story1["stages"]))
