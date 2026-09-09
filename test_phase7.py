import os
import subprocess
import time
import requests
import sys

print("Starting Uvicorn...")
uvicorn_proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"])

for _ in range(30):
    try:
        requests.get("http://localhost:8000/health")
        break
    except requests.exceptions.ConnectionError:
        time.sleep(1)

try:
    print("Fetching incidents...")
    res_inc = requests.get("http://localhost:8000/api/incidents")
    incidents = res_inc.json()["incidents"]
    
    if not incidents:
        print("No incidents found, populating...")
        subprocess.run([sys.executable, "test_phase5.py"], check=True)
        res_inc = requests.get("http://localhost:8000/api/incidents")
        incidents = res_inc.json()["incidents"]

    open_incidents = [i for i in incidents if i["status"] == "open"]
    
    total = len(open_incidents)
    critical = len([i for i in open_incidents if i["risk_level"] == "Critical"])
    high = len([i for i in open_incidents if i["risk_level"] == "High"])
    medium = len([i for i in open_incidents if i["risk_level"] == "Medium"])
    low = len([i for i in open_incidents if i["risk_level"] == "Low"])
    
    print("Testing /api/reports/summary?format=md")
    res_sum_md = requests.get("http://localhost:8000/api/reports/summary?format=md")
    assert res_sum_md.status_code == 200
    sum_md = res_sum_md.text
    
    # Assert counts match
    assert f"**Total Open Incidents:** {total}" in sum_md
    assert f"**Critical:** {critical}" in sum_md
    assert f"**High:** {high}" in sum_md
    
    print("Testing /api/reports/summary?format=pdf")
    res_sum_pdf = requests.get("http://localhost:8000/api/reports/summary?format=pdf")
    assert res_sum_pdf.status_code == 200
    assert res_sum_pdf.content.startswith(b"%PDF")
    
    highest_inc = sorted(incidents, key=lambda x: x["score"], reverse=True)[0]
    hid = highest_inc["id"]
    
    print(f"Testing /api/reports/{hid}?format=md")
    res_inc_md = requests.get(f"http://localhost:8000/api/reports/{hid}?format=md")
    assert res_inc_md.status_code == 200
    
    print("\n--- HUMAN READABLE INCIDENT REPORT ---")
    print(res_inc_md.text)
    print("--------------------------------------\n")
    
    print(f"Testing /api/reports/{hid}?format=pdf")
    res_inc_pdf = requests.get(f"http://localhost:8000/api/reports/{hid}?format=pdf")
    assert res_inc_pdf.status_code == 200
    assert res_inc_pdf.content.startswith(b"%PDF")
    
    print("ALL TESTS PASSED!")

except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
