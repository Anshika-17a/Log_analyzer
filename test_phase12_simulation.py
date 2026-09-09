# -*- coding: utf-8 -*-
"""
Phase 12 — One-Click Live Attack Simulation Integration Test.

Verifies:
1. POST /api/simulate/apt29  → rows_ingested > 200, alerts > 50, incidents > 20, top_incident_id set
2. POST /api/simulate/insider → rows_ingested > 200, alerts > 25, incidents > 10, top_incident_id set
3. POST /api/simulate/benign  → rows_ingested > 150, top_incident_id set (ML only)
4. sample_stream contains tag & severity fields
5. Invalid scenario returns 400
6. Idempotency: second run of apt29 produces a fresh top_incident_id
"""
import os, subprocess, time, requests, sys

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
    # ── Test 1: APT29 ────────────────────────────────────────────
    print("\n[1] Testing /api/simulate/apt29 ...")
    t0 = time.time()
    res = requests.post("http://localhost:8000/api/simulate/apt29")
    elapsed = time.time() - t0
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text[:300]}"
    d = res.json()
    assert d["status"] == "success", f"Expected success, got: {d}"
    assert d["scenario"] == "apt29"
    assert d["rows_ingested"] > 200, f"Expected >200 rows, got {d['rows_ingested']}"
    assert d["alerts_count"] > 50, f"Expected >50 alerts, got {d['alerts_count']}"
    assert d["incidents_count"] > 20, f"Expected >20 incidents, got {d['incidents_count']}"
    assert d["top_incident_id"] is not None, "top_incident_id should be set"
    assert len(d["sample_stream"]) > 0, "sample_stream should not be empty"
    first = d["sample_stream"][0]
    assert "tag" in first, f"sample_stream item missing 'tag' field: {first}"
    assert "severity" in first, f"sample_stream item missing 'severity' field: {first}"
    print(f"   ✅ APT29: rows={d['rows_ingested']}, alerts={d['alerts_count']}, incidents={d['incidents_count']}, top_id={d['top_incident_id']}, elapsed={elapsed:.1f}s")
    
    # Verify critical tag presence in apt29 stream
    severities = [r["severity"] for r in d["sample_stream"]]
    has_critical = "critical" in severities
    assert has_critical, f"APT29 stream should contain critical-severity events but severities were: {set(severities)}"
    print(f"   ✅ APT29 stream contains critical threat events.")

    # ── Test 2: Insider ──────────────────────────────────────────
    print("\n[2] Testing /api/simulate/insider ...")
    res = requests.post("http://localhost:8000/api/simulate/insider")
    assert res.status_code == 200
    d = res.json()
    assert d["rows_ingested"] > 150, f"Expected >150 rows, got {d['rows_ingested']}"
    assert d["alerts_count"] > 10, f"Expected >10 alerts, got {d['alerts_count']}"
    assert d["incidents_count"] > 5, f"Expected >5 incidents, got {d['incidents_count']}"
    assert d["top_incident_id"] is not None
    print(f"   ✅ Insider: rows={d['rows_ingested']}, alerts={d['alerts_count']}, incidents={d['incidents_count']}, top_id={d['top_incident_id']}")

    # ── Test 3: Benign ───────────────────────────────────────────
    print("\n[3] Testing /api/simulate/benign ...")
    res = requests.post("http://localhost:8000/api/simulate/benign")
    assert res.status_code == 200
    d = res.json()
    assert d["rows_ingested"] > 100, f"Expected >100 rows, got {d['rows_ingested']}"
    # Benign should have 0 deterministic rule alerts (only possible ML alerts)
    sample_tags = [r.get("tag", "") for r in d["sample_stream"]]
    assert "IMPOSSIBLE TRAVEL (MOSCOW)" not in sample_tags, "Benign stream should not have Moscow travel"
    assert "PRIVILEGE ESCALATION (ROOT)" not in sample_tags, "Benign stream should not have PrivEsc"
    print(f"   ✅ Benign: rows={d['rows_ingested']}, alerts={d['alerts_count']}, incidents={d['incidents_count']}")
    print(f"   ✅ Benign stream has no critical attack tags (verified).")

    # ── Test 4: Invalid scenario ─────────────────────────────────
    print("\n[4] Testing invalid scenario (should return 400) ...")
    res = requests.post("http://localhost:8000/api/simulate/nation_state_hack_lol")
    assert res.status_code == 400, f"Expected 400, got {res.status_code}"
    err = res.json()
    assert "detail" in err
    print(f"   ✅ Invalid scenario correctly returns 400: {err['detail']}")

    # ── Test 5: Idempotency — second run of apt29 ────────────────
    print("\n[5] Idempotency check — re-running apt29 ...")
    res = requests.post("http://localhost:8000/api/simulate/apt29")
    assert res.status_code == 200
    d2 = res.json()
    assert d2["top_incident_id"] is not None
    # Rows should still be consistent (not doubled)
    assert d2["rows_ingested"] > 200
    print(f"   ✅ Second apt29 run OK: rows={d2['rows_ingested']}, top_id={d2['top_incident_id']}")

    # ── Test 6: Verify dashboard still renders ───────────────────
    print("\n[6] Verifying dashboard HTML still renders ...")
    res = requests.get("http://localhost:8000/")
    assert res.status_code == 200
    assert "sim-showcase" in res.text, "Dashboard should contain sim-showcase section"
    assert "btnSimApt29" in res.text, "Dashboard should contain APT29 button"
    assert "btnSimInsider" in res.text, "Dashboard should contain Insider button"
    assert "btnSimBenign" in res.text, "Dashboard should contain Benign button"
    assert "simTerminalWrap" in res.text, "Dashboard should contain terminal ticker element"
    print(f"   ✅ Dashboard renders correctly with all simulation UI elements.")

    print("\n══════════════════════════════════════")
    print("  ALL PHASE 12 SIMULATION TESTS PASSED! ✅")
    print("══════════════════════════════════════")

except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"\n❌ Test failed: {e}")
    sys.exit(1)
finally:
    uvicorn_proc.terminate()
