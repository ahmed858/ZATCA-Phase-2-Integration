import frappe
import json
import requests
 


def get_first_csid_call(otp, csr, integration_type):
    '''first CSID call 
    take:-
    otp: to authrize the call,
    csr: the certifcation that hold the data
    '''
    
    try:
        url = (
            f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/compliance"
        )

        payload = json.dumps({"csr": csr})

        headers = {
            "OTP": otp,
            "Accept-Version": "v2",
            "Content-Type": "application/json",
        }
        response = requests.request("POST", url, headers=headers, data=payload)

        return response
    except Exception as e:
        frappe.throw(f"Error while get first CSID call: {e}" )