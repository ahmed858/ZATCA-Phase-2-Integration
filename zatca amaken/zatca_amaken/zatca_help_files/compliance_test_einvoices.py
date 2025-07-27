import requests
import requests
import json
import hasher

import base64
import xml.etree.ElementTree as ET


def get_hash_test_invoices():

    Invoices = []
    invoice_hash, encoded_invoice = hasher.get_invoice_hash("AmakenStandardInvoice.xml")
    UUID = hasher.get_uuid_from_xml("AmakenStandardInvoice.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))

    invoice_hash, encoded_invoice = hasher.get_invoice_hash(
        "AmakenStandardCreditNote.xml"
    )
    UUID = hasher.get_uuid_from_xml("AmakenStandardCreditNote.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))

    invoice_hash, encoded_invoice = hasher.get_invoice_hash(
        "AmakenStandardDebitNoe.xml"
    )
    UUID = hasher.get_uuid_from_xml("AmakenStandardDebitNoe.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))
    return Invoices


def compliance_invoices(username, password):
    try:

        url = (
            "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/compliance/invoices"
        )

        Invoices = get_hash_test_invoices()

        # Concatenate username and password, then encode as bytes before encoding in base64
        token = username + ":" + password
        token_bytes = token.encode("utf-8")  # Encode the string to bytes
        token_base64 = base64.b64encode(token_bytes).decode(
            "utf-8"
        )  # Base64 encode the bytes
        for invoice in Invoices:
            invoice_hash = invoice[0]
            UUID = invoice[1]
            encoded_invoice = invoice[2]
            print(UUID)
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

            response = requests.post(url, headers=headers, data=payload)
            if response.status_code == 200:
                print("Success")
                print(response.json())
                print("")
            else:
                print("Error")
                print(response.status_code)
                print(response.text)
                print("")
                raise Exception("Error")
    except Exception as e:
        raise e


U = "TUlJQ2RqQ0NBaDJnQXdJQkFnSUdBWlpvSFloK01Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3TkRJME1UUXdORFF6V2hjTk16QXdOREl6TWpFd01EQXdXakNCcHpFTE1Ba0dBMVVFQmhNQ1UwRXhFekFSQmdOVkJBc01Dak14TURNd05qZzJNRE14UnpCRkJnTlZCQW9NUHRpMDJMSFpnOWlwSU5pajJZWFlwOW1EMllZZzJZall0Tml4MllyWmc5bUhJTm1FMllUWXF0bUMyWXJaaXRtRklOaW4yWVRZdWRtQzJLZllzZG1LTVRvd09BWURWUVFERERIWXROaXgyWVBZcVNEWXA5bUYyS2ZaZzltR0lObUUyWVRZcXRtQzJZclppdG1GSU5pbjJZVFl1ZG1DMktmWXNkbUtNRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRVVUMWd5QndOeVo0eU9DcUxxQnIyQk1iQU5vdkxCLzhsOXpZYWUvbTZDU3NPSjVSLzIxRUNuLy9wSVlIamlxcDcraXU3c1F4QkZWajdMRGptKy9ueXY2T0J5RENCeFRBTUJnTlZIUk1CQWY4RUFqQUFNSUcwQmdOVkhSRUVnYXd3Z2Fta2dhWXdnYU14T2pBNEJnTlZCQVFNTVRFdFFVMUJTMFZPZkRJdFlXMWhhMlZ1ZkRNdFpXUXlNbVl4WkRndFpUWmhNaTB4TVRFNExUbGlOVGd0WkRsaE9HWXhIekFkQmdvSmtpYUprL0lzWkFFQkRBOHpNVEF6TURZNE5qQXpNREF3TURNeERUQUxCZ05WQkF3TUJERXdNREF4RHpBTkJnTlZCQm9NQm5KcGVXRmthREVrTUNJR0ExVUVEd3diMktyWXJOaW4yTEhZcVNEWXA5bUUyTG5aZ3RpbjJMSFlwOWlxTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUFxcS9qZXp3dlFYeG1TMVVHY2ZVanJEb3lQK21tWFJWUU14Wm45UE5QRmdBaUFsVFEyYjREcjdubFlkNG9XRnA0R3ZIeW9OOGxNUGd0eE4xUW9ydkI1bnFnPT0="
P = "0TREIW6Or4XjJt0GR2Jtlz+dGxYaGMhKqjHKJhOgWsk="

print(compliance_invoices(U, P))
