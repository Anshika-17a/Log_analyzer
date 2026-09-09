import os
import subprocess
import time
import requests
import sys
import sqlite3

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
    
    with open("data/sample_logs.csv", "rb") as f:
        requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    
    print("Generating alerts & incidents...")
    requests.get("http://localhost:8000/api/alerts")
    res_inc = requests.get("http://localhost:8000/api/incidents")
    incidents = res_inc.json()["incidents"]
    
    if not incidents:
        print("No incidents generated!")
        sys.exit(1)
        
    first_id = incidents[0]["id"]
    
    print(f"Checking GET /api/incidents/{first_id} ...")
    res_detail = requests.get(f"http://localhost:8000/api/incidents/{first_id}")
    detail = res_detail.json()
    assert "recommended_actions" in detail
    assert len(detail["recommended_actions"]) > 0
    print(f"Found {len(detail['recommended_actions'])} actions for Incident {first_id}.")
    
    print("Testing PUT /api/incidents/status ...")
    res_put = requests.put(f"http://localhost:8000/api/incidents/{first_id}/status", json={"status": "reviewing", "changed_by": "analyst1"})
    assert res_put.status_code == 200, f"PUT failed: {res_put.text}"
    
    print("Testing Invalid Status ...")
    res_bad = requests.put(f"http://localhost:8000/api/incidents/{first_id}/status", json={"status": "invalid_status"})
    assert res_bad.status_code == 422
    
    print("Checking SQLite audit_log ...")
    conn = sqlite3.connect("logs.db")
    audit_logs = conn.execute("select * from audit_log order by id desc limit 3").fetchall()
    print("Audit Logs:")
    for al in audit_logs:
        print(al)
    assert len(audit_logs) == 1
    assert audit_logs[0][4] == "reviewing"
    
    print("Checking OpenAPI docs ...")
    res_docs = requests.get("http://localhost:8000/openapi.json")
    assert res_docs.status_code == 200
    docs = res_docs.json()
    assert "IncidentDetailResponse" in docs["components"]["schemas"]
    print("OpenAPI schema rendered successfully!")
    
    print("ALL TESTS PASSED!")
    
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
