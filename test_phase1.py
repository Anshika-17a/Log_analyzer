import os
import subprocess
import time
import requests
import sys

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
    start_t = time.time()
    with open("data/sample_logs.csv", "rb") as f:
        res = requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    end_t = time.time()
    data = res.json()
    print(f"500 rows upload response: {data} in {end_t - start_t:.2f}s")
    assert data["rows_inserted"] == 500 or (data["rows_inserted"] + data["rows_skipped"] == 500), "Missing rows in 500 upload"
    assert end_t - start_t < 3.5, "500 rows upload took too long"
    
    # 4. Generate 10k rows
    print("Generating 10000 rows...")
    subprocess.run([sys.executable, "data/gen_synthetic_logs.py", "--rows", "10000", "--out", "data/sample_10k.csv"], check=True)
    
    # 5. Upload 10k rows
    print("Uploading 10000 rows...")
    start_t = time.time()
    with open("data/sample_10k.csv", "rb") as f:
        res = requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    end_t = time.time()
    data = res.json()
    print(f"10k rows upload response: {data} in {end_t - start_t:.2f}s")
    assert data["rows_inserted"] == 10000 or (data["rows_inserted"] + data["rows_skipped"] == 10000), "Missing rows in 10k upload"
    assert end_t - start_t < 15, "10k rows upload took too long"
    
    # 6. Corrupt one row
    print("Testing corrupted row...")
    with open("data/sample_logs.csv", "r") as f:
        lines = f.readlines()
    # Find a row and empty its src_ip (column index 4: timestamp,user_id,event_type,resource,src_ip,status)
    parts = lines[1].split(',')
    parts[4] = ""
    lines[1] = ",".join(parts)
    with open("data/corrupt_logs.csv", "w") as f:
        f.writelines(lines)
        
    with open("data/corrupt_logs.csv", "rb") as f:
        res = requests.post("http://localhost:8000/api/logs/upload", files={"file": f})
    data = res.json()
    print(f"Corrupt row upload response: {data}")
    assert data["rows_skipped"] > 0, "Corrupt row should have been skipped"
    
    # 7. GET /api/logs?page=1&page_size=20
    print("Testing GET /api/logs...")
    res = requests.get("http://localhost:8000/api/logs?page=1&page_size=20")
    data = res.json()
    assert len(data["logs"]) == 20, "Expected 20 logs in response"
    print(f"GET /api/logs returned {len(data['logs'])} items successfully.")
    
    print("ALL TESTS PASSED!")

except Exception as e:
    print(f"Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
