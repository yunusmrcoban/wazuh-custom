import requests
import base64
import json
from datetime import datetime, timedelta
import logging

# Logging configuration
logging.basicConfig(
    filename="debug.log",  # Log file path
    level=logging.DEBUG,  # Log debug and higher levels
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format: time - level - message
    datefmt="%Y-%m-%d %H:%M:%S"  # Date format
)

logger = logging.getLogger()

# Define variables
organization = "org_id"  # Organization name
pat = "PAT"  # Personal access token
format_type = "json"  # Log format
api_version = "7.2-preview.1"  # API version

try:
    logger.info("Script execution started.")

    # Time calculations
    end_time = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"  # Current time (UTC)
    start_time = (datetime.utcnow() - timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"  # 5 minutes ago
    logger.debug(f"Time range: startTime={start_time}, endTime={end_time}")

    # API URL
    url = f"https://auditservice.dev.azure.com/{organization}/_apis/audit/downloadlog?format={format_type}&startTime={start_time}&endTime={end_time}&api-version={api_version}"
    logger.debug(f"API URL: {url}")

    # Base64 encoding for PAT authentication
    token = base64.b64encode(f":{pat}".encode()).decode("ascii")
    headers = {
        "Authorization": f"Basic {token}",
        "Accept": "application/json"
    }
    logger.debug("Authentication header created.")

    # Fetch logs
    response = requests.get(url, headers=headers)
    logger.debug(f"API request sent. Status code: {response.status_code}")

    if response.status_code == 200:
        try:
            # Parse JSON response
            audit_logs = response.json()
            logger.info(f"Audit logs retrieved. Total log count: {len(audit_logs)}")

            # Write to JSONL file
            with open("AzureDevops_Audit_logs.json", "a", encoding="utf-8") as f:  # Absolute path
                for log in audit_logs:
                    # Create a new dictionary with "AzureDevops." prefix for all keys except Logtype
                    enriched_log = {"Logtype": "AzureDevops"}
                    for key, value in log.items():
                        if key != "Logtype":  # Skip Logtype key
                            new_key = f"AzureDevops.{key}"
                            enriched_log[new_key] = value
                        else:
                            enriched_log[key] = value  # Keep Logtype as is

                    # Extract PermissionNames from EventSummary if present and expand into numbered fields
                    if "AzureDevops.Data" in enriched_log and isinstance(enriched_log["AzureDevops.Data"], dict):
                        data = enriched_log["AzureDevops.Data"]
                        if "EventSummary" in data and isinstance(data["EventSummary"], list):
                            permission_names = [item.get("PermissionNames", "") for item in data["EventSummary"] if isinstance(item, dict)]
                            if permission_names:
                                # Assign each permission to a numbered field without extra quotes
                                for index, permission in enumerate(permission_names, 1):
                                    enriched_log[f"AzureDevops.PermissionNames{index}"] = permission
                                # Keep the original comma-separated list for reference
                                enriched_log["AzureDevops.PermissionNames"] = ", ".join(filter(None, permission_names))

                    # Write each log as a single line JSON
                    f.write(json.dumps(enriched_log) + "\n")

            logger.info("Logs saved to 'AzureDevops_Audit_logs.json' in JSONL format.")
            
        except ValueError as e:
            logger.error(f"Response is not in JSON format. Error: {e}")
            logger.debug(f"Raw response: {response.text}")
    else:
        logger.error(f"Failed to retrieve logs. Error: {response.status_code}, {response.text}")

except Exception as e:
    logger.error(f"General error occurred: {e}", exc_info=True)

finally:
    logger.info("Script execution completed.")
