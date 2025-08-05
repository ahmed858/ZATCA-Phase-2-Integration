import requests
import json
import  utils.token as tkn

def send_invoice(username,password,invoice_hash,UUID,encoded_invoice,URL):
    try:
        token_base64 = tkn.get_authHeader(username,password)
        headers = {
                    "Accept-Version": "v2",
                    "Accept-Language": "en",
                    "request-from": "zatca-service",
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {token_base64}",
                }
        payload = json.dumps(
                    {
                        "invoiceHash": invoice_hash,
                        "uuid": UUID,
                        "invoice": encoded_invoice,
                    }
                )
        return requests.request("POST",url=URL,headers=headers,data=payload)
    except Exception as e:
        frappe.throw(e)

    