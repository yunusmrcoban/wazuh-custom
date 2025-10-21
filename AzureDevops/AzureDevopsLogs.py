import requests
import json
import time
import uuid
from datetime import datetime, timedelta
import logging
import os


# Logging configuration
#logging.basicConfig(
#    level=logging.DEBUG,  # Log debug and higher levels
#    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format: time - level - #message
#    datefmt="%Y-%m-%d %H:%M:%S"  # Date format
#)
#logger = logging.getLogger()

# Define variables
organization = ""  # Organization name
client_id = ""  # Application (client) ID from Entra ID
tenant_id = ""  # Entra ID tenant ID
client_secret = ""  # Client secret from Entra ID
format_type = "json"  # Log format
api_version = "7.2-preview.1"  # API version

def get_access_token():
    """Fetch access token from Microsoft Entra ID using client secret."""
    try:
        logger.debug("Requesting access token using client secret.")
        token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": ""
        }
        response = requests.post(token_endpoint, data=data)
        if response.status_code == 200:
            access_token = response.json().get("access_token")
            logger.debug("Access token retrieved successfully.")
            return access_token
        else:
                   logger.error(f"Failed to retrieve access token. Status: {response.status_code}, Error: {response.text}")
                   return None
    except Exception as e:
        logger.error(f"Error retrieving access token: {e}", exc_info=True)
        return None

try:
    logger.info("Script execution started.")

    # Get access token
    access_token = get_access_token()
    if not access_token:
        logger.error("Aborting due to failure in retrieving access token.")
        raise Exception("Failed to retrieve access token.")

    # Time calculations
    end_time = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"  # Current time (UTC)
    start_time = (datetime.utcnow() - timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"  # 5 minutes ago
    logger.debug(f"Time range: startTime={start_time}, endTime={end_time}")

    # API URL
    url = f"https://auditservice.dev.azure.com/{organization}/_apis/audit/downloadlog?format={format_type}&startTime={start_time}&endTime={end_time}&api-version={api_version}"
    logger.debug(f"API URL: {url}")
    
    # Headers with Bearer token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    logger.debug("Authentication header created with Bearer token.")

    # Fetch logs
    response = requests.get(url, headers=headers)
    logger.debug(f"API request sent. Status code: {response.status_code}")

    if response.status_code == 200:
        try:
            # Parse JSON response
            audit_logs = response.json()
            logger.info(f"Audit logs retrieved. Total log count: {len(audit_logs)}")

            # Process logs (write to console or file)
            enriched_logs = []
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

                enriched_logs.append(enriched_log)
            # Output logs (to console or file)
            for enriched_log in enriched_logs:
                print(json.dumps(enriched_log))  # Output to console
                # If running locally and file output is desired, uncomment below:
                with open("/var/log/AzureDevops/AzureDevops_Audit_logs.json", "a", encoding="utf-8") as f:
                     f.write(json.dumps(enriched_log) + "\n")

            logger.info("Logs processed and output successfully.")
            
        except ValueError as e:
            logger.error(f"Response is not in JSON format. Error: {e}")
            logger.debug(f"Raw response: {response.text}")
    else:
        logger.error(f"Failed to retrieve logs. Error: {response.status_code}, {response.text}")

except Exception as e:
    logger.error(f"General error occurred: {e}", exc_info=True)

finally:
    logger.info("Script execution completed.")
