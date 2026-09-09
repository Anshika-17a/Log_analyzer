#!/bin/bash
set -e

echo "--- SECURITY LOG ANALYZER DEMO SCRIPT ---"
echo "1. Health Check..."
curl -s http://localhost:8000/health

echo -e "\n2. Generate Synthetic Data..."
python data/gen_synthetic_logs.py --rows 500

echo "3. Upload Logs..."
curl -s -F "file=@data/sample_logs.csv" http://localhost:8000/api/logs/upload

echo -e "\n4. Generate Alerts..."
curl -s http://localhost:8000/api/alerts > /dev/null
echo "Alerts generated successfully."

echo -e "\n5. Generate Incidents..."
# Get first incident ID
INC_ID=$(curl -s http://localhost:8000/api/incidents | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
echo "Highest incident ID is $INC_ID"

echo -e "\n6. Fetch Incident Details..."
curl -s http://localhost:8000/api/incidents/$INC_ID > /dev/null
echo "Incident details fetched successfully."

echo -e "\n7. Update Incident Status..."
curl -s -X PUT -H "Content-Type: application/json" -d '{"status":"reviewing"}' http://localhost:8000/api/incidents/$INC_ID/status

echo -e "\n8. Fetch Human-Readable Report..."
curl -s http://localhost:8000/api/reports/$INC_ID?format=md | head -n 5

echo -e "\n9. Fetch Org Summary Report..."
curl -s http://localhost:8000/api/reports/summary?format=md | head -n 5

echo -e "\n10. Check Dashboard Route..."
curl -s http://localhost:8000/ | grep "<h1>"

echo -e "\nDEMO SCRIPT COMPLETE!"
