import os
import subprocess
import time
import requests
import sys

if os.path.exists("logs.db"):
    os.remove("logs.db")

print("Starting Uvicorn...")
uvicorn_proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"])

for _ in range(30):
    try:
        requests.get("http://localhost:8000/health")
        break
    except requests.exceptions.ConnectionError:
        time.sleep(1)

try:
    print("Generating 500 rows...")
    subprocess.run([sys.executable, "data/gen_synthetic_logs.py", "--rows", "500", "--out", "data/sample_logs.csv"], check=True)
    
    print("Uploading 500 rows...")
    with open("data/sample_logs.csv", "rb") as f:
        requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    
    print("Generating alerts (Phase 2 & 3)...")
    res_alerts = requests.get("http://localhost:8000/api/alerts")
    alert_data = res_alerts.json()
    total_alerts = alert_data["alerts_generated"]
    print(f"Total alerts generated: {total_alerts}")
    
    print("Correlating into incidents (Phase 4)...")
    res_incidents = requests.get("http://localhost:8000/api/incidents")
    incidents_data = res_incidents.json()
    incidents = incidents_data["incidents"]
    total_incidents = len(incidents)
    print(f"Total incidents: {total_incidents}")
    
    assert 10 <= total_incidents <= 45, f"Expected ~20-30 incidents, got {total_incidents}"
    
    critical_incident = None
    for incident in incidents:
        if incident["score"] >= 85:
            res_detail = requests.get(f"http://localhost:8000/api/incidents/{incident['id']}")
            detail = res_detail.json()
            
            # Check if there are at least 2 distinct signal types
            # "ML Behavioral Anomaly" and another rule, or two different rules.
            rules = detail["rules_fired"]
            if len(rules) >= 2:
                critical_incident = detail
                break
                    
    assert critical_incident is not None, "Could not find a critical incident with mixed signals"
    print(f"Found mixed-signal Critical Incident ID {critical_incident['incident']['id']} with Score {critical_incident['incident']['score']}")
    print(f"Rules fired: {critical_incident['rules_fired']}")
    print("ALL TESTS PASSED!")
    
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
