import requests
import json

### This code manages the API requestes made for getting the enichment details from Abuse IPDB and VirusTotal.

def request_manager(action_endpoint, headers, request_type="GET",
                    params=None, payload=None,
                    **kwargs):
    try:        
        if request_type == "GET":
            api_req = requests.get(
                action_endpoint,
                headers=headers,
                params=params
            )
        action_status_code = api_req.status_code

        if action_status_code >=200 and action_status_code <400:
            action_response = {
                "action_response": api_req.json(),
                "status_code": str(action_status_code),
                "action_status": "SUCCESS"
            }
        if action_status_code >= 400 and action_status_code < 500:
            action_response = {
                "action_response": api_req.json(),
                "status_code": str(action_status_code),
                "action_status": "ERROR"
            }
        if action_status_code >=500:
            action_response = {
                "action_response": api_req.json(),
                "status_code": str(action_status_code),
                "action_status": "ERROR"
            }
    except Exception as e:
        action_response = {
            "action_response": "Error! Something went wrong!",
            "action_status": "Exception Ocurred! FAILED",
            "Exception_error": str(e)
        }
    
    return action_response