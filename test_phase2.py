import os
import subprocess
import time
import requests
import sys

# Clear DB for a clean test
if os.path.exists("logs.db"):
    os.remove("logs.db")

# 1. Start uvicorn
print("Starting Uvicorn...")
uvicorn_proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"])

# Wait for server to start
for _ in range(30):
    try:
        requests.get("http://localhost:8000/health")
        break
    except requests.exceptions.ConnectionError:
        time.sleep(1)

try:
    # 2. Generate 500 rows
    print("Generating 500 rows...")
    subprocess.run([sys.executable, "data/gen_synthetic_logs.py", "--rows", "500", "--out", "data/sample_logs.csv"], check=True)
    
    # 3. Upload 500 rows
    print("Uploading 500 rows...")
    with open("data/sample_logs.csv", "rb") as f:
        requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    
    # 4. Generate alerts
    print("Fetching alerts (run 1)...")
    start_t = time.time()
    res = requests.get("http://localhost:8000/api/alerts")
    end_t = time.time()
    data = res.json()
    assert end_t - start_t < 5.0, f"Rule evaluation took too long: {end_t - start_t:.2f}s"
    
    alerts = data["alerts"]
    total_alerts = len(alerts)
    print(f"Total alerts generated: {total_alerts} in {end_t - start_t:.2f}s")
    
    # verify rules fired
    fired_rules = set(a["rule_id"] for a in alerts)
    expected_rules = {"brute_force_001", "priv_esc_001", "recon_001", "off_hours_001", "impossible_travel_001", "exfil_burst_001", "dormant_account_001"}
    missing = expected_rules - fired_rules
    assert not missing, f"Missing rules: {missing}"
    
    # verify evidence is specific and non-empty
    for a in alerts:
        ev = a["evidence"]
        assert ev and len(ev) > 10, "Evidence is missing or too generic"
        # ensure it names the user or something specific
        assert "User" in ev, "Evidence must name the user"
        
    assert 40 <= total_alerts <= 100, f"Total alerts {total_alerts} is outside 40-100 range"
    
    # 5. Idempotency test
    print("Fetching alerts (run 2)...")
    res2 = requests.get("http://localhost:8000/api/alerts")
    data2 = res2.json()
    total_alerts2 = len(data2["alerts"])
    print(f"Total alerts run 2: {total_alerts2}")
    assert total_alerts == total_alerts2, f"Idempotency failed: {total_alerts} != {total_alerts2}"
    
    print("ALL TESTS PASSED!")

except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
