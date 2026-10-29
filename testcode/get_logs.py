import google.auth
from google.cloud import logging

# Autodetect Project
_, project_id = google.auth.default()
logging_client = logging.Client(project=project_id)

# Filter for Model Armor logs
FILTER = "resource.type=\"modelarmor.googleapis.com/SanitizeOperation\""

print(f"Retrieving Model Armor logs for project: {project_id}...\n")

# Retrieve and print logs
entries = logging_client.list_entries(filter_=FILTER, max_results=5)
count = 0
for entry in entries:
    count += 1
    payload = entry.payload
    print(f"--- LOG ENTRY {count} ({entry.timestamp}) ---")
    print(f"Operation: {payload.get('operationType')}")
    print(f"Input Text: {payload.get('sanitizationInput', {}).get('text')}")
    print(f"Verdict Reason: {payload.get('sanitizationVerdictReason')}\n")

if count == 0:
    print("No logs found. Ensure you are in the correct project and logging is active on your templates.")
