import os
import re
import uuid
import xml.etree.ElementTree as ET
import frappe
from frappe.utils.data import get_time
from frappe.utils import today
from . import helper, hasher
from lxml import etree

CBC_ID = "cbc:ID"
DS_TRANSFORM = "ds:Transform"


# ahmed 4\7\2025 11:37
# create UBL scema tags and xml namespace baesed on zatca standards


def salesinvoice_data(invoice, invoice_number, additional_fields_doc,log_doc,zatca_amaken_settings_doc):
    """
    Populates the Sales Invoice XML with key elements and metadata.
    """
    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)
        # standard invoice without signing.xml
        # i build this example
        # same arrange
        invoice, additional_fields_doc = invoice_Header(
            invoice=invoice,
            invoice_number=invoice_number,
            additional_fields_doc=additional_fields_doc,
            log_doc=log_doc,zatca_amaken_settings_doc=zatca_amaken_settings_doc
        )

        ###########################################################
        ##########TAX Buyer info            #######################
        ###########################################################
        invoice = helper.add_SupplierParty(
            invoice=invoice, invoice_number=invoice_number
            ,log_doc=log_doc
        )

        ###########################################################
        ##########customer TAX info         #######################
        ###########################################################
        invoice = helper.add_CustomerParty(
            invoice=invoice, invoice_number=invoice_number,
            log_doc=log_doc
        )

        cac_Delivery = ET.SubElement(invoice, "cac:Delivery")
        cbc_actual_delivery_date = ET.SubElement(cac_Delivery, "cbc:ActualDeliveryDate")
        cbc_actual_delivery_date.text = today()

        cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
        cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
        cbc_PaymentMeansCode.text = "30"
        # <cbc:InstructionNote>CANCELLATION_OR_TERMINATION</cbc:InstructionNote>
        if sales_invoice_doc.credit_note_reason or sales_invoice_doc.debit_note_reason:

            cbc_InstructionNote = ET.SubElement(cac_PaymentMeans, "cbc:InstructionNote")
            cbc_InstructionNote.text = (
                sales_invoice_doc.credit_note_reason
                if sales_invoice_doc.credit_note_reason
                else sales_invoice_doc.debit_note_reason
            )
        # print("cbc_InstructionNote ok
        # print("PaymentMeansCode ok")
        ###########################################################
        ##########allownce charges         #######################
        ###########################################################
        invoice = add_AllownceCharges(invoice=invoice, invoice_number=invoice_number,log_doc=log_doc)
        # print(" add_AllownceCharges  ok ")

        invoice = add_tax_section(invoice=invoice, invoice_number=invoice_number,log_doc=log_doc)
        # print("add_tax_section  ok ")
        invoice = helper.add_invoiceLines(
            invoice=invoice, invoice_number=invoice_number,
            log_doc=log_doc
        )
        
        additional_fields_doc.save(ignore_permissions=True)
        log_doc.save(ignore_permissions=True)
        return invoice, additional_fields_doc  # , uuid1, sales_invoice_doc

    except Exception as e:
        frappe.msgprint(("Error occurred in SalesInvoice data: " f"{str(e)}"))
        additional_fields_doc.save(ignore_permissions=True)
        log_doc.coding_error = (log_doc.coding_error or '') + ';'+ str( "erorro in sales invoice data method",e)
        log_doc.save(ignore_permissions=True)        
        return invoice, additional_fields_doc  # , uuid1, sales_


@frappe.whitelist(allow_guest=False)
def gen(doc, additional_fields_doc,log_doc,zatca_amaken_settings_doc):
    invoice_number = doc.name
    # invoice = xml_tags()
    invoice = ET.Element(
        "Invoice", xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
    )
    invoice.set(
        "xmlns:cac",
        "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    )
    invoice.set(
        "xmlns:cbc",
        "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    )
    invoice.set(
        "xmlns:ext",
        "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    )
    # create additional seles invoice  doc to pass it with sales invoice after complite save it in database

    invoice, additional_fields_doc = salesinvoice_data(
        invoice=invoice,
        invoice_number=invoice_number,
        additional_fields_doc=additional_fields_doc,
        log_doc=log_doc,
        zatca_amaken_settings_doc=zatca_amaken_settings_doc
    )

    
    try:
        tree = ET.ElementTree(invoice)

        # Save to a file
        app_path = frappe.get_app_path("zatca_amaken")
        # print(app_path)
        output_path = os.path.join(
            app_path, "zatca_help_files", "amakentemp_invoice.xml"
        )

        tree.write(
            # f"{frappe.local.site}/private/files/zatca_E-invoices/final_standardinvoice.xml",
            output_path,
            encoding="utf-8",
            xml_declaration=True,
        )

        # frappe.msgprint("done" + "!" * 100)
        return invoice, additional_fields_doc
    except Exception as e:
        frappe.msgprint('error' + str(e) )
        additional_fields_doc.save()
        log_doc.coding_error = (log_doc.coding_error or '') + ';'+ str( "errror in generate while try to convert to xml data method",e)
        log_doc.save(ignore_permissions=True)   
        return None, None

def invoice_Header(invoice, invoice_number, additional_fields_doc,log_doc,zatca_amaken_settings_doc):
    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)

        cbc_profile_id = ET.SubElement(invoice, "cbc:ProfileID")
        cbc_profile_id.text = "reporting:1.0"

        cbc_id = ET.SubElement(invoice, CBC_ID)
        cbc_id.text = str(sales_invoice_doc.name)

        cbc_uuid = ET.SubElement(invoice, "cbc:UUID")
        cbc_uuid.text = str(uuid.uuid1())
        uuid1 = cbc_uuid.text
        additional_fields_doc.uuid = uuid1

        cbc_issue_date = ET.SubElement(invoice, "cbc:IssueDate")
        cbc_issue_date.text = (
            sales_invoice_doc.posting_date.strftime("%Y-%m-%d")
            if hasattr(sales_invoice_doc.posting_date, "strftime")
            else str(sales_invoice_doc.posting_date)
        )

        cbc_issue_time = ET.SubElement(invoice, "cbc:IssueTime")
        cbc_issue_time.text = helper.get_issue_time(invoice_number)

        additional_fields_doc.last_attempt = (
            f"{cbc_issue_date.text}-{cbc_issue_time.text}"
        )

        cbc_invoice_type_code = ET.SubElement(invoice, "cbc:InvoiceTypeCode")

        invoice_type_code = ""
        invoice_type_name = ""

        if sales_invoice_doc.is_return:
            invoice_type_code = "381"
            invoice_type_name = "0211010"
        elif sales_invoice_doc.is_debit_note:
            invoice_type_code = "383"
            invoice_type_name = "0211010"
        else:
            invoice_type_code = "388"

        if sales_invoice_doc.custom_b2c:
            invoice_type_name = "0200000"
        else:
        #     #standard
            invoice_type_name = "0100000"

        cbc_invoice_type_code.set("name", invoice_type_name)
        cbc_invoice_type_code.text = invoice_type_code
        additional_fields_doc.invoice_type_code = invoice_type_code
        additional_fields_doc.invoice_type_transaction = invoice_type_name

        # <cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode>
        cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
        cbc_DocumentCurrencyCode.text = "SAR"
        # <cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>
        cbc_tax_currency_code = ET.SubElement(invoice, "cbc:TaxCurrencyCode")
        cbc_tax_currency_code.text = "SAR"

        # add billing refrance here
        # Error if: the accountant make a credit / debit note to invoice not sended to zatca
        if sales_invoice_doc.return_against:
            bill_refrance_name = sales_invoice_doc.return_against
            
            # any invoice sended to zatca additional invoice fields was created
            # try to get if there is no additional field throw error about you need to send bill refrance before make a credit / debit note
            if frappe.db.exists("Sales Invoice Additional Fields",{
                "invoice_reference":bill_refrance_name,
                "integration_type":zatca_amaken_settings_doc.integration_type,
                }):
                
                bill_additional_fields_doc = frappe.get_doc(
                    "Sales Invoice Additional Fields",
                    {
                "invoice_reference":bill_refrance_name,
                "integration_type": zatca_amaken_settings_doc.integration_type,})
                status = bill_additional_fields_doc.integration_status
                if  status != "Accepted" and status!="Accepted with warnings":
                    frappe.throw(f"يجب إرسال الفاتورة {bill_refrance_name} قبل إرسال إشعار دائن .")

 
            
                # bill_refrance_id = bill_additional_fields_doc.invoice_counter  # zatca counter

                cac_BillingReference = ET.SubElement(invoice, "cac:BillingReference")
                cac_InvoiceDocumentReference = ET.SubElement(
                    cac_BillingReference, "cac:InvoiceDocumentReference"
                )
                cbc_ID = ET.SubElement(cac_InvoiceDocumentReference, "cbc:ID")
                cbc_ID.text = bill_refrance_name

                

        ###########################################################
        #######Additional document refrance #######################
        ###########################################################
        additional_doc_ref = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
        cbc_id_icv = ET.SubElement(additional_doc_ref, "cbc:ID")
        cbc_id_icv.text = "ICV"

        # counter for zatca

        company = sales_invoice_doc.company
        countername = frappe.db.get_value(
            "Zatca Invoice Counting Settings", {"company_counter_for": company,
                                                "zatca_settings_reference":zatca_amaken_settings_doc.name}, 
                                                "name")
        counter_doc = frappe.get_doc("Zatca Invoice Counting Settings", countername)
        cur_value = counter_doc.get("invoice_counter")

        cbc_uuid_icv = ET.SubElement(additional_doc_ref, "cbc:UUID")
        cbc_uuid_icv.text = str(
            cur_value + 1
        )  # You can dynamically set this later if needed

        additional_doc_ref_pih = ET.SubElement(
            invoice, "cac:AdditionalDocumentReference"
        )

        cbc_id_pih = ET.SubElement(additional_doc_ref_pih, "cbc:ID")
        cbc_id_pih.text = "PIH"
        cac_attachment = ET.SubElement(additional_doc_ref_pih, "cac:Attachment")
        embedded_object = ET.SubElement(
            cac_attachment, "cbc:EmbeddedDocumentBinaryObject"
        )
        embedded_object.set("mimeCode", "text/plain")
        cur_PIH = counter_doc.get("previous_invoice_hash")
        embedded_object.text = cur_PIH
        additional_fields_doc.previous_invoice_hash = cur_PIH
        additional_fields_doc.invoice_counter = cur_value + 1

        additional_fields_doc.save()
        return invoice, additional_fields_doc
    except Exception as e:
        frappe.msgprint('حدث خطأ في إضافة البيانات إلى الفاتورة: {}'.format(e))
        log_doc.coding_error = (log_doc.coding_error or '') +';'+ str(e)
        log_doc.save(ignore_permissions=True)
        additional_fields_doc.save()
        return invoice, additional_fields_doc
    
def add_AllownceCharges(invoice, invoice_number,log_doc):

    try:
        allowance = False  # by defualt no allownce
        if not allowance:
            cac_AllowanceCharge = ET.SubElement(invoice, "cac:AllowanceCharge")
            cbc_ChargeIndicator = ET.SubElement(
                cac_AllowanceCharge, "cbc:ChargeIndicator"
            )
            cbc_ChargeIndicator.text = "false"
            cbc_AllowanceChargeReasonCode = ET.SubElement(
                cac_AllowanceCharge, "cbc:AllowanceChargeReasonCode"
            )
            cbc_AllowanceChargeReasonCode.text = "None"
            cbc_AllowanceChargeReason = ET.SubElement(
                cac_AllowanceCharge, "cbc:AllowanceChargeReason"
            )
            cbc_AllowanceChargeReason.text = "None"

            cbc_Amount = ET.SubElement(cac_AllowanceCharge, "cbc:Amount")
            cbc_Amount.text = "0.00"
            cbc_Amount.set("currencyID", "SAR")
            cac_AllowanceCharge = add_15VAT_tax_category(root=cac_AllowanceCharge)

        return invoice
    except Exception as e:
        frappe.msgprint(f"error in add allownce functiion{e}")
        log_doc.coding_error = (log_doc.coding_error or '') +';'+ str(e)
        log_doc.save(ignore_permissions=True)
        return invoice


def add_15VAT_tax_category(root):

    try:
        tax_category = ET.SubElement(root, "cac:TaxCategory")

        cbc_id = ET.SubElement(tax_category, "cbc:ID")
        cbc_id.text = "S"

        cbc_percent = ET.SubElement(tax_category, "cbc:Percent")
        cbc_percent.text = "15.00"

        tax_scheme = ET.SubElement(tax_category, "cac:TaxScheme")
        tax_scheme_id = ET.SubElement(tax_scheme, "cbc:ID")
        tax_scheme_id.text = "VAT"
        return root
    except Exception as e:
        frappe.throw(f"error in add_15VAT_tax_category functiion{e}")
        return


def add_tax_section(invoice, invoice_number,log_doc):
    try:
        salesinvoice_doc = frappe.get_doc("Sales Invoice", invoice_number)
        total_tax_amount_vlue_over_invoice = round(
            abs(salesinvoice_doc.total_taxes_and_charges), 2
        )

        total_with_VAT_value = round(
            abs(salesinvoice_doc.base_rounded_total), 2
        )  # total with vat
        total_without_VAT_value = round(abs(salesinvoice_doc.total), 2)  # total without vat

        # First <cac:TaxTotal> block
        tax_total1 = ET.SubElement(invoice, "cac:TaxTotal")
        tax_amount1 = ET.SubElement(tax_total1, "cbc:TaxAmount", {"currencyID": "SAR"})
        tax_amount1.text = str(total_tax_amount_vlue_over_invoice)

        # Second <cac:TaxTotal> block
        tax_total2 = ET.SubElement(invoice, "cac:TaxTotal")
        tax_amount2 = ET.SubElement(tax_total2, "cbc:TaxAmount", {"currencyID": "SAR"})
        tax_amount2.text = str(total_tax_amount_vlue_over_invoice)

        tax_subtotal = ET.SubElement(tax_total2, "cac:TaxSubtotal")

        taxable_amount = ET.SubElement(
            tax_subtotal, "cbc:TaxableAmount", {"currencyID": "SAR"}
        )
        taxable_amount.text = str(total_without_VAT_value)

        tax_amount_sub = ET.SubElement(
            tax_subtotal, "cbc:TaxAmount", {"currencyID": "SAR"}
        )
        tax_amount_sub.text = str(total_tax_amount_vlue_over_invoice)
        tax_subtotal = add_15VAT_tax_category(root=tax_subtotal)

        #################################################################################

        cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")

        cbc_LineExtensionAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:LineExtensionAmount"
        )
        cbc_LineExtensionAmount.set("currencyID", "SAR")
        cbc_LineExtensionAmount.text = str(total_without_VAT_value)

        cbc_TaxExclusiveAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount"
        )
        cbc_TaxExclusiveAmount.set("currencyID", "SAR")
        cbc_TaxExclusiveAmount.text = str(total_without_VAT_value)

        cbc_TaxInclusiveAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount"
        )
        cbc_TaxInclusiveAmount.set("currencyID", "SAR")
        cbc_TaxInclusiveAmount.text = str(total_with_VAT_value)

        cbc_AllowanceTotalAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount"
        )
        cbc_AllowanceTotalAmount.set("currencyID", "SAR")
        cbc_AllowanceTotalAmount.text = "0.00"

        cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")

        cbc_PayableAmount.set("currencyID", "SAR")
        cbc_PayableAmount.text = str(total_with_VAT_value)

        return invoice

    except Exception as e:
        frappe.msgprint(f"error in add_tax_section functiion{e}")
        log_doc.coding_error = (log_doc.coding_error or '') +';'+ str("add_tax_section :"+e)
        log_doc.save(ignore_permissions=True)
        return
