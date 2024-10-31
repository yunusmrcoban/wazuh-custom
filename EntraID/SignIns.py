import sys
import os
import logging
from datetime import datetime, timedelta, timezone  # timezone is defined here
import requests
import msal
from dateutil import parser as date_parser
import argparse

# =============================
# **CONFIGURATION SECTION**
# =============================

# Azure AD Application Credentials
TENANT_ID = 'TENANTID' #change_me
CLIENT_ID = 'CLIENTID' #change_me
CLIENT_SECRET = 'CLIENTSECRET' #change_me 
# Log File Settings (Full Path)
LOG_FILE = 'LOGFILEPATH/EntraID-signIns.log' #change_me

# Last Processed Timestamp File (Full Path)
LAST_PROCESSED_FILE = 'LOGFILEPATH/last_processed_timestamp.txt' #change_me

# =============================
# **LOGGING SETTINGS**
# =============================

# Set the logging level to WARNING to log only WARNING and ERROR level messages
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,  # Lower the level to only log WARNING and above
    format='%(asctime)s EntraIDSignIns=%(message)s',
    datefmt='%b %d %H:%M:%S'
)

logger = logging.getLogger(__name__)

# =============================
# **ARGUMENT PARSING**
# =============================

def get_args():
    parser = argparse.ArgumentParser(description='Export Microsoft Entra ID sign-in logs in syslog format.')
    parser.add_argument('--RiskySignInsOnly', action='store_true', help='Export only risky sign-in attempts.')
    parser.add_argument('--GuestUserSignInsOnly', action='store_true', help='Export only guest user sign-ins.')
    parser.add_argument('--Success', action='store_true', help='Export only successful sign-ins.')
    parser.add_argument('--Failure', action='store_true', help='Export only failed sign-ins.')
    parser.add_argument('--InteractiveOnly', action='store_true', help='Export only interactive sign-ins.')
    parser.add_argument('--NonInteractiveOnly', action='store_true', help='Export only non-interactive sign-ins.')
    parser.add_argument('--CAPNotAppliedOnly', action='store_true', help='Export sign-ins where Conditional Access Policies were not applied.')
    parser.add_argument('--CAPAppliedOnly', action='store_true', help='Export sign-ins where Conditional Access Policies were applied.')
    parser.add_argument('--CAPSuccessOnly', action='store_true', help='Export sign-ins where Conditional Access Policies were successfully applied.')
    parser.add_argument('--CAPFailedOnly', action='store_true', help='Export sign-ins where Conditional Access Policies failed.')
    parser.add_argument('--UserPrincipalName', nargs='*', help='Filter by specific user(s) based on UPN.')
    return parser.parse_args()

# =============================
# **AUTHENTICATION**
# =============================

def authenticate():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    scope = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=authority
    )

    result = app.acquire_token_for_client(scopes=scope)

    if "access_token" in result:
        return result['access_token']
    else:
        logger.error(f"Authentication failed: {result.get('error')} - {result.get('error_description')}")
        sys.exit(1)

# =============================
# **FETCHING SIGN-IN LOGS**
# =============================

def fetch_sign_ins(token, start_time):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = 'https://graph.microsoft.com/v1.0/auditLogs/signIns'
    
    # Time in the correct format to create the filter
    # ISO 8601 format 'yyyy-mm-ddThh:mm:ssZ'
    filter_time = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')  # UTC time
    params = {
        '$filter': f'createdDateTime ge {filter_time}',
        '$orderby': 'createdDateTime asc',
        '$top': 999  # Adjust as needed
    }
    sign_ins = []
    while url:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            logger.error(f"Failed to fetch sign-ins: {response.status_code} - {response.text}")
            return []
        data = response.json()
        fetched = data.get('value', [])
        sign_ins.extend(fetched)
        url = data.get('@odata.nextLink', None)
        params = {}  # @odata.nextLink already contains all necessary parameters
    return sign_ins

# =============================
# **FILTERING SIGN-IN LOGS**
# =============================

def filter_sign_ins(sign_ins, args):
    filtered = []
    for sign_in in sign_ins:
        # Status Filtering
        error_code = sign_in.get('status', {}).get('errorCode')
        status = 'Success' if error_code == 0 else 'Failed'
        if args.Success and status != 'Success':
            continue
        if args.Failure and status != 'Failed':
            continue

        # Conditional Access Filters
        ca_status = sign_in.get('conditionalAccessStatus', 'unknown').lower()
        if args.CAPAppliedOnly and ca_status == 'notapplied':
            continue
        if args.CAPNotAppliedOnly and ca_status != 'notapplied':
            continue
        if args.CAPSuccessOnly and ca_status != 'success':
            continue
        if args.CAPFailedOnly and ca_status != 'failure':
            continue

        # Risky Sign-Ins
        risk_detail = sign_in.get('riskDetail', 'none').lower()
        if args.RiskySignInsOnly and risk_detail == 'none':
            continue

        # Guest Users
        user_type = sign_in.get('userType', 'member').lower()
        if args.GuestUserSignInsOnly and user_type == 'member':
            continue

        # Specific Users
        if args.UserPrincipalName:
            if sign_in.get('userPrincipalName') not in args.UserPrincipalName:
                continue

        # Interactive Filters
        is_interactive = sign_in.get('isInteractive', False)
        if args.InteractiveOnly and not is_interactive:
            continue
        if args.NonInteractiveOnly and is_interactive:
            continue

        filtered.append(sign_in)
    return filtered

# =============================
# **CREATING LOGS IN SYSLOG FORMAT**
# =============================

def format_syslog(sign_in):
    timestamp = sign_in.get('createdDateTime')
    try:
        timestamp = date_parser.parse(timestamp).strftime('%b %d %H:%M:%S')
    except Exception:
        timestamp = datetime.utcnow().strftime('%b %d %H:%M:%S')
    
    user_display_name = sign_in.get('userDisplayName', 'Unknown')
    user_principal_name = sign_in.get('userPrincipalName', 'Unknown')
    status = 'Success' if sign_in.get('status', {}).get('errorCode') == 0 else 'Failed'
    ip_address = sign_in.get('ipAddress', 'Unknown')
    location = sign_in.get('location', {})
    city = location.get('city', 'Unknown')
    state = location.get('state', 'Unknown')
    country = location.get('countryOrRegion', 'Unknown')
    device_detail = sign_in.get('deviceDetail', {})
    device_name = device_detail.get('displayName', 'Unknown')
    browser = device_detail.get('browser', 'Unknown')
    os = device_detail.get('operatingSystem', 'Unknown')
    user_type = sign_in.get('userType', 'member')
    auth_requirement = sign_in.get('authenticationRequirement', 'Unknown')
    risk_detail = sign_in.get('riskDetail', 'none')
    risk_state = sign_in.get('riskState', 'unknown')
    ca_status = sign_in.get('conditionalAccessStatus', 'unknown')
    applied_policies = sign_in.get('appliedConditionalAccessPolicies', [])
    applied_policies_names = ", ".join([policy.get('displayName', 'Unknown') for policy in applied_policies if policy.get('result', '').lower() in ['success', 'failed']]) or "None"
    is_interactive = sign_in.get('isInteractive', False)
    # Application Info
    app_display_name = sign_in.get('appDisplayName', 'Unknown')
    application_info = app_display_name
    # Construct message in the desired format
    message = (f"OK User={user_principal_name} "
               f"Situation={status} IP={ip_address} Location={city} {country} "
               f"Device={device_name} Browser='{browser}' OS={os} "
               f"UserType={user_type} AuthReq={auth_requirement} RiskDetail={risk_detail} "
               f"RiskState={risk_state} CAStatus={ca_status} AppliedPolicies='{applied_policies_names}' "
               f"Application='{application_info}' Interactive={is_interactive}")
    
    return message

# =============================
# **READING LAST PROCESSED TIMESTAMP**
# =============================

def read_last_processed_time():
    if not os.path.exists(LAST_PROCESSED_FILE):
        # If the file does not exist, take 5 minutes ago as default
        return datetime.utcnow() - timedelta(minutes=5)
    with open(LAST_PROCESSED_FILE, 'r') as f:
        timestamp_str = f.read().strip()
        try:
            return date_parser.parse(timestamp_str)
        except Exception:
            # If the file content is invalid, take 5 minutes ago as default
            return datetime.utcnow() - timedelta(minutes=5)

# =============================
# **WRITING LAST PROCESSED TIMESTAMP**
# =============================

def write_last_processed_time(latest_time):
    try:
        with open(LAST_PROCESSED_FILE, 'w') as f:
            # Write in ISO 8601 format (UTC with 'Z' suffix)
            f.write(latest_time.strftime('%Y-%m-%dT%H:%M:%SZ'))
    except Exception as e:
        logger.error(f"An error occurred while writing to last_processed_timestamp.txt: {str(e)}")

# =============================
# **MAIN FUNCTION**
# =============================

def main():
    args = get_args()
    
    try:
        token = authenticate()
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        sys.exit(1)
    
    try:
        last_processed_time = read_last_processed_time()
    except Exception as e:
        logger.error(f"Failed to read last processed time: {str(e)}")
        last_processed_time = datetime.utcnow() - timedelta(minutes=5)  # Use default value
    
    try:
        sign_ins = fetch_sign_ins(token, last_processed_time)
        
        if not sign_ins:
            # Do not log if no new sign-in records are found
            pass
        else:
            filtered_sign_ins = filter_sign_ins(sign_ins, args)
            
            for sign_in in filtered_sign_ins:
                syslog_message = format_syslog(sign_in)
                logger.warning(syslog_message)  # Log at WARNING level to avoid INFO level logs
            
            # Update the last processed timestamp
            latest_time = max([date_parser.parse(sign_in.get('createdDateTime')) for sign_in in sign_ins])
            # Convert to UTC and format with 'Z' suffix
            latest_time_utc = latest_time.astimezone(timezone.utc)
            write_last_processed_time(latest_time_utc)
    
    except Exception as e:
        logger.error(f"An error occurred during sign-in processing: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
