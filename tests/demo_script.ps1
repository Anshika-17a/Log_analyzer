$ErrorActionPreference = "Stop"

Write-Host "--- SECURITY LOG ANALYZER DEMO SCRIPT ---"
Write-Host "1. Health Check..."
$res = Invoke-RestMethod -Uri http://localhost:8000/health
Write-Host "Health: $($res.status)"

Write-Host "2. Generate Synthetic Data..."
python data/gen_synthetic_logs.py --rows 500

Write-Host "3. Upload Logs..."
$upload = curl.exe -s -F "file=@data/sample_logs.csv" http://localhost:8000/api/logs/upload
Write-Host "Upload Response: $upload"

Write-Host "4. Generate Alerts..."
$alerts = Invoke-RestMethod -Uri http://localhost:8000/api/alerts
Write-Host "Alerts Generated: $($alerts.alerts.Length)"

Write-Host "5. Generate Incidents..."
$incidents = Invoke-RestMethod -Uri http://localhost:8000/api/incidents
Write-Host "Incidents Generated: $($incidents.incidents.Length)"

$highest_id = $incidents.incidents[0].id
Write-Host "Highest incident ID is $highest_id"

Write-Host "6. Fetch Incident Details..."
$details = Invoke-RestMethod -Uri http://localhost:8000/api/incidents/$highest_id
Write-Host "Incident details fetched successfully"

Write-Host "7. Update Incident Status..."
$update = Invoke-RestMethod -Uri http://localhost:8000/api/incidents/$highest_id/status -Method Put -Body '{"status":"reviewing"}' -ContentType "application/json"
Write-Host "Update Status: $($update.status)"

Write-Host "8. Fetch Human-Readable Report..."
$report = curl.exe -s "http://localhost:8000/api/reports/$highest_id`?format=md"
Write-Host "Report fetched successfully."

Write-Host "9. Fetch Org Summary Report..."
$summary = curl.exe -s "http://localhost:8000/api/reports/summary?format=md"
Write-Host "Summary Report fetched successfully."

Write-Host "10. Check Dashboard Route..."
$dash = curl.exe -s http://localhost:8000/ | findstr "<h1>"
Write-Host "Dashboard: $dash"

Write-Host "`nDEMO SCRIPT COMPLETE!"
