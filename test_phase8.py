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
    highest_inc = sorted(incidents, key=lambda x: x["score"], reverse=True)[0]
    hid = highest_inc["id"]
    
    print(f"Testing /api/incidents/{hid}/narrative")
    res_nar = requests.get(f"http://localhost:8000/api/incidents/{hid}/narrative")
    
    if res_nar.status_code != 200:
        print(f"FAILED: Status {res_nar.status_code}")
        print(res_nar.text)
    else:
        print("\n--- AI NARRATIVE ---")
        print(res_nar.json()["narrative"])
        print("--------------------\n")
        print("ALL TESTS PASSED!")

except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Test failed: {e}")
finally:
    uvicorn_proc.terminate()
