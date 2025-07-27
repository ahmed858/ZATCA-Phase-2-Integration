import frappe
import requests
import json
from . import helper

import requests
import requests
import json
from . import hasher

import base64
import xml.etree.ElementTree as ET
 

def get_first_csid_call(otp, csr, integration_type):
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
        frappe.throw("Error in get_CSID: {}".format(e))


def compliance_test_invoices_call(username, password, integration_type,company_name):
    try:

        url = f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/compliance/invoices"

        Invoices = helper.get_hash_test_invoices(company_name= company_name)
        # frappe.msgprint(Invoices)
        # Concatenate username and password, then encode as bytes before encoding in base64
        token = username + ":" + password
        token_bytes = token.encode("utf-8")  # Encode the string to bytes
        token_base64 = base64.b64encode(token_bytes).decode(
            "utf-8"
        )  # Base64 encode the bytes
        ok = True
        zatca_return_text = ""
        x = 1
        # print("Invoices", Invoices)
        for invoice in Invoices:
            invoice_hash = invoice[0]
            UUID = invoice[1]
            encoded_invoice = invoice[2]
            # print(UUID)
            # Create the
            payload = json.dumps(
                {
                    "invoiceHash": invoice_hash,
                    "uuid": UUID,
                    "invoice": encoded_invoice,
                }
            )

            headers = {
                "Accept-Version": "v2",
                "Accept-Language": "en",
                "request-from": "zatca-service",
                "Content-Type": "application/json",
                "Authorization": f"Basic {token_base64}",  # Add the token here
            }
            # Send Request 
            response = requests.post(url, headers=headers, data=payload)
            acceptable_statuses = (200, 201, 208)
            if  response.status_code not in acceptable_statuses :
                ok = False
                zatca_return_text = response.text
                break

            x += 1
        if ok:
            frappe.msgprint(f"All {x} invoices are OK")
            return 1
        else:
            frappe.msgprint(f" invoices {x}are not OK {zatca_return_text}")
            return zatca_return_text
    except Exception as e:
        frappe.throw(e)


def get_production_csid_call(
    username, password, compliance_request_id, integration_type
):
    try:
        frappe.msgprint(integration_type)
        url = f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/production/csids"

        payload = json.dumps({"compliance_request_id": compliance_request_id})

        # Concatenate username and password, then encode as bytes before encoding in base64
        token = username + ":" + password
        token_bytes = token.encode("utf-8")  # Encode the string to bytes
        token_base64 = base64.b64encode(token_bytes).decode(
            "utf-8"
        )  # Base64 encode the bytes

        headers = {
            "Accept-Version": "V2",
            "Content-Type": "application/json",
            "Authorization": f"Basic {token_base64}",
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code == 200:
            return response
        else:
            frappe.throw(f"{response.text}")

    except requests.exceptions.HTTPError as http_err:
        frappe.throw(f"HTTP error occurred: {http_err} - {response.text}")
    except requests.exceptions.RequestException as req_err:
        frappe.throw(f"Request error: {req_err}")
    except Exception as e:
        frappe.throw(f"Unexpected error: {e}")


def clearance_invoice_call(
    username, password, invoice_hash, UUID, encoded_invoice, integration_type
):
    url = f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/invoices/clearance/single"
    # Concatenate username and password, then encode as bytes before encoding in base64
    token = username + ":" + password
    token_bytes = token.encode("utf-8")  # Encode the string to bytes
    token_base64 = base64.b64encode(token_bytes).decode(
        "utf-8"
    )  # Base64 encode the bytes

    payload = json.dumps(
        {
            "invoiceHash": invoice_hash,
            "uuid": UUID,
            "invoice": encoded_invoice,
        }
    )

    headers = {
        "Accept-Version": "v2",
        "Accept-Language": "ar",
        "request-from": "zatca-service",
        "Content-Type": "application/json",
        "Authorization": f"Basic {token_base64}",  # Add the token here
    }

    return requests.request("POST", url, headers=headers, data=payload)
