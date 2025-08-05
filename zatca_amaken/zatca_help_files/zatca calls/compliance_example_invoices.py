from send_invoice import send_invoice
import helper
import frappe 

def compliance_example_invoices(username, password, integration_type,company_name):
    try:
        url = f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{integration_type}/compliance/invoices"

        Invoices = helper.get_hash_test_invoices(company_name= company_name)
        
        # variables to catch where is the error
        zatca_return_text = ""
        x = 1
 
        for invoice in Invoices:
            invoice_hash = invoice[0]
            UUID = invoice[1]
            encoded_invoice = invoice[2]

            response = send_invoice(username, password, invoice_hash, UUID, encoded_invoice, url)

            acceptable_status = [200,202,208]
            if response.status_code not in acceptable_status:

                zatca_return_text = response.text
                break
            x+=1
        return {"count":x, "error":zatca_return_text}
    except Exception as e:
        frappe.throw(f'{e}')


