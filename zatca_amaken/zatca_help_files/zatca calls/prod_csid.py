import frappe
import requests
import base64
import json
from token import get_authHeader 

def get_production_csid_call( username, password, 
                             compliance_request_id, integration_type):
    '''Production CSID call 
        take:-
        username,
        password, 
        compliance_request_id,
        integration_type
    '''
    try:
        url = f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/production/csids"

        payload = json.dumps({"compliance_request_id": compliance_request_id})

        # # Concatenate username and password, then encode as bytes before encoding in base64
        # token = username + ":" + password
        # token_bytes = token.encode("utf-8")  # Encode the string to bytes
        # token_base64 = base64.b64encode(token_bytes).decode(
        #     "utf-8"
        # )  # Base64 encode the bytes

        auth_head = get_authHeader(username, password)
        headers = {
            "Accept-Version": "V2",
            "Content-Type": "application/json",
            "Authorization" :auth_head 
            # "Authorization": f"Basic {token_base64}",
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        return response
        if response.status_code == 200:
            return response
        else:
            frappe.throw(f"{response.text}")

    except Exception as e:
        frappe.throw('Error while get production CSID ')

