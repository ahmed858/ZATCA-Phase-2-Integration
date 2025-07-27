from lxml import etree
import frappe
import qrcode
from frappe.utils.file_manager import save_file
from frappe.model.delete_doc import delete_doc
from io import BytesIO
from .zatca_calls import (
    get_first_csid_call,
    get_production_csid_call,
    compliance_test_invoices_call,
    clearance_invoice_call,
)
import hashlib
import base64
import requests
import requests
import json
from . import hasher
from . import einvoice_generator
import base64
import xml.etree.ElementTree as ET




@frappe.whitelist()
def temp_zatca_notification(doc=None,temp=None):
    if temp:
        return frappe._("الفاتورة لم ترسل للهيئة الربط تحت التطوير الرجاء الانتظار حتي الانتهاء.")
    
    frappe.msgprint(frappe._("الفاتورة لم ترسل للهيئة الربط تحت التطوير الرجاء الانتظار حتي الانتهاء."))



def get_hash_test_invoices(company_name):
    company_folder = ''
    if company_name == 'شركة أماكن للتقييم العقاري':
        company_folder ='Amaken Appraisal Example Invoices'
    elif company_name == 'شركة مجموعة أماكن الدولية':
        company_folder ='Amaken Group Example Invoices'
    else:
        frappe.throw(frappe._('No test invoice to this company'))
        
    frappe.msgprint(company_folder)
    Invoices = []
    # 1
    invoice_hash, encoded_invoice = hasher.get_invoice_hash(f"{company_folder}/StandardInvoice.xml")
    UUID = hasher.get_uuid_from_xml(f"{company_folder}/StandardInvoice.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))
    
    # 2
    invoice_hash, encoded_invoice = hasher.get_invoice_hash(f"{company_folder}/StandardCreditNote.xml")
    UUID = hasher.get_uuid_from_xml(f"{company_folder}/StandardCreditNote.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))
    
    # 3
    invoice_hash, encoded_invoice = hasher.get_invoice_hash(f"{company_folder}/StandardDebitNote.xml")
    UUID = hasher.get_uuid_from_xml(f"{company_folder}/StandardDebitNote.xml")
    Invoices.append((invoice_hash, UUID, encoded_invoice))
    
    
    # # 4
    # invoice_hash, encoded_invoice = hasher.get_invoice_hash("Simplified_Invoice.xml")
    # UUID = hasher.get_uuid_from_xml("Simplified_Invoice.xml")
    # Invoices.append((invoice_hash, UUID, encoded_invoice))
    # # 5

    # invoice_hash, encoded_invoice = hasher.get_invoice_hash("Simplified_Debit_Note.xml")
    # UUID = hasher.get_uuid_from_xml("Simplified_Debit_Note.xml")
    # Invoices.append((invoice_hash, UUID, encoded_invoice))
    # # 6
    # invoice_hash, encoded_invoice = hasher.get_invoice_hash(
    #     "Simplified_Credit_Note.xml"
    # )
    # UUID = hasher.get_uuid_from_xml("Simplified_Credit_Note.xml")
    # Invoices.append((invoice_hash, UUID, encoded_invoice))

    return Invoices


@frappe.whitelist()
def get_first_csid(ZATCA_settings_name, otp):
    try:
        # Fetch the zatca amaken settings document
        ZATCA_settings_doc = frappe.get_doc(
            "zatca amaken settings", ZATCA_settings_name
        )
        encodedcsr = ZATCA_settings_doc.csr
        integration_type = ZATCA_settings_doc.integration_type
        # Call the external ZATCA function
        response = get_first_csid_call(otp, encodedcsr, integration_type)

        if response.status_code == 200:
            data = response.json()

            ZATCA_settings_doc.first_binary_security_token = data.get(
                "binarySecurityToken"
            )
            ZATCA_settings_doc.first_secret = data.get("secret")
            ZATCA_settings_doc.first_request_id = data.get("requestID")
            ZATCA_settings_doc.first_csid_errors = "None"
            ZATCA_settings_doc.save(ignore_permissions=True)
            return 1
        else:

            ZATCA_settings_doc.first_csid_errors = str(response.text)
            ZATCA_settings_doc.save(ignore_permissions=True)

            return -1
    except Exception as e:
        frappe.throw(f"Exception in get_first_csid: {str(e)} - {ZATCA_settings_name}")


@frappe.whitelist()
def compliance_test_invoices(ZATCA_settings_name):
    try:
        ZATCA_settings_doc = frappe.get_doc(
            "zatca amaken settings", ZATCA_settings_name
        )

        U = ZATCA_settings_doc.first_binary_security_token
        P = ZATCA_settings_doc.first_secret
        integration_type = ZATCA_settings_doc.integration_type

        res = compliance_test_invoices_call(
            username=U, password=P, integration_type=integration_type,company_name = ZATCA_settings_doc.company
        )

        if res != 1:
            return res

        return 1
    except Exception as e:
        frappe.throw(
            f"Exception in compliance_test_invoices: {str(e)} - {ZATCA_settings_name}"
        )


@frappe.whitelist()
def get_production_csid(ZATCA_settings_name):
    try:
        ZATCA_settings_doc = frappe.get_doc(
            "zatca amaken settings", ZATCA_settings_name
        )

        U = ZATCA_settings_doc.first_binary_security_token
        P = ZATCA_settings_doc.first_secret
        first_request_id = ZATCA_settings_doc.first_request_id

        integration_type = ZATCA_settings_doc.integration_type

        response = get_production_csid_call(
            username=U,
            password=P,
            compliance_request_id=first_request_id,
            integration_type=integration_type,
        )
        if response.status_code == 200:
            data = response.json()
            ZATCA_settings_doc.production_binary_security_token = data.get(
                "binarySecurityToken"
            )
            ZATCA_settings_doc.production_secret = data.get("secret")
            ZATCA_settings_doc.production_request_id = data.get("requestID")
            ZATCA_settings_doc.first_csid_errors = "None"
            ZATCA_settings_doc.save(ignore_permissions=True)

            return 1
    except Exception as e:
        frappe.throw(f"Error while get production CSID:\n {e}")
        return None

    ## save the data in


import os
import re
import uuid
import xml.etree.ElementTree as ET
import frappe
from frappe.utils.data import get_time
from frappe.utils import today


def add_SupplierParty(invoice, invoice_number,log_doc):
    try:

        AccountingSupplierParty_tag = ET.SubElement(
            invoice, "cac:AccountingSupplierParty"
        )
        Party_tag = ET.SubElement(AccountingSupplierParty_tag, "cac:Party")

        # Party Identification
        PartyIdentification_tag = ET.SubElement(Party_tag, "cac:PartyIdentification")
        PartyIdentification_ID_tag = ET.SubElement(PartyIdentification_tag, "cbc:ID")
        PartyIdentification_ID_tag.set("schemeID", "CRN")
        PartyIdentification_ID_tag.text = "1010443011"  # رقم السجل التجاري

        # Postal Address
        PostalAddress_tag = ET.SubElement(Party_tag, "cac:PostalAddress")
        ET.SubElement(PostalAddress_tag, "cbc:StreetName").text = (
            "الدائري الشرقي الفرعي | Eastern Ring Branch"
        )
        ET.SubElement(PostalAddress_tag, "cbc:BuildingNumber").text = "6805"
        ET.SubElement(PostalAddress_tag, "cbc:CitySubdivisionName").text = (
            "الريان | Al Rayan"
        )
        ET.SubElement(PostalAddress_tag, "cbc:CityName").text = "الرياض | Riyadh"
        ET.SubElement(PostalAddress_tag, "cbc:PostalZone").text = "14213"
        ET.SubElement(PostalAddress_tag, "cbc:CountrySubentity").text = "Saudi Arabia"

        Country_tag = ET.SubElement(PostalAddress_tag, "cac:Country")
        ET.SubElement(Country_tag, "cbc:IdentificationCode").text = "SA"

        # Tax Info
        PartyTaxScheme_tag = ET.SubElement(Party_tag, "cac:PartyTaxScheme")
        ET.SubElement(PartyTaxScheme_tag, "cbc:CompanyID").text = "310306860300003"
        TaxScheme_tag = ET.SubElement(PartyTaxScheme_tag, "cac:TaxScheme")
        ET.SubElement(TaxScheme_tag, "cbc:ID").text = "VAT"

        # Legal Entity
        PartyLegalEntity = ET.SubElement(Party_tag, "cac:PartyLegalEntity")
        ET.SubElement(PartyLegalEntity, "cbc:RegistrationName").text = (
            "شركة أماكن وشريكه للتقييم العقاري | Amaken and Partner Real Estate Appraisal Company"
        )
        return invoice
    except Exception as e:
        frappe.msgprint(
            "حدث خطأ في إضافة بيانات المورد: {0}"
        )
        log_doc.coding_error = (log_doc.coding_error or '') +  str(e)
        log_doc.save(ignore_permissions=True)
        return invoice


def add_CustomerParty(invoice, invoice_number,log_doc):
    try:
        """if simplifaied invoice not nessary addressfor customer"""
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)
        customer_doc = frappe.get_doc("Customer", sales_invoice_doc.customer)
        
        # Root: AccountingCustomerParty
        AccountingCustomerParty_tag = ET.SubElement(
            invoice, "cac:AccountingCustomerParty"
        )

        if sales_invoice_doc.custom_b2c:
            frappe.msgprint(frappe._( "الفواتير المبسطة لا تعمل في الوقت الحالي."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+"try to send simple invoices"
            log_doc.save()
            return invoice
        result = frappe.db.sql("""
        SELECT parent
        FROM `tabDynamic Link`
        WHERE link_doctype = 'Customer' AND link_name = %s AND parenttype = 'Address'
            """, customer_doc.name, as_dict=True)

        if not result:
            frappe.msgprint(frappe._( "لايوجد عنوان للعميل."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no linked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice
            
        # try to fetch address from customer 
        address_name = result[0].parent
        customer_address_doc = frappe.get_doc("Address", address_name)
    
 
        street_name = customer_address_doc.street_names
        if not street_name or not street_name.strip():
            
            frappe.msgprint(frappe._( f"الرجاء ادخال اسم الشارع في العنوان{customer_address_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no street_name inlinked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice

        building_number = customer_address_doc.custom_building_number
        if not building_number or not building_number.strip():
            frappe.msgprint(frappe._( f"الرجاء ادخال رقم المبني في العنوان{customer_address_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no building_number inlinked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice

        city = customer_address_doc.city
        if not city or not city.strip():
            frappe.msgprint(frappe._( f"الرجاء ادخال المدينة في العنوان{customer_address_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no city inlinked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice
        county = customer_address_doc.county
        if not county or not county.strip():
            frappe.msgprint(frappe._( f"الرجاء ادخال الحي في العنوان{customer_address_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no county inlinked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice



        postal_code = customer_address_doc.pincode
        if not postal_code or not str(postal_code).strip():
            frappe.msgprint(frappe._( f"الرجاء ادخال الرقم البريدي  في العنوان{customer_address_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no postal_code inlinked address for customer {customer_doc.name}"
            log_doc.save()
            return invoice

        Party_tag = ET.SubElement(AccountingCustomerParty_tag, "cac:Party")

        # Party Identification
        if not customer_doc.tax_id:
            frappe.msgprint(frappe._( f"  الرجاء ادخال الرقم الضريبي للعميل{customer_doc.name}."))
            log_doc.coding_error = (log_doc.coding_error or '') +';'+f"there is no tax_id  for customer {customer_doc.name}"
            log_doc.save()
            return invoice

        PartyIdentification_tag = ET.SubElement(Party_tag, "cac:PartyIdentification")
        PartyIdentification_ID_tag = ET.SubElement(PartyIdentification_tag, "cbc:ID")
        PartyIdentification_ID_tag.set("schemeID", "NAT")
        PartyIdentification_ID_tag.text = customer_doc.tax_id

        # Postal Address
        PostalAddress_tag = ET.SubElement(Party_tag, "cac:PostalAddress")
        ET.SubElement(PostalAddress_tag, "cbc:StreetName").text = street_name
        ET.SubElement(PostalAddress_tag, "cbc:BuildingNumber").text = building_number
        # ET.SubElement(PostalAddress_tag, "cbc:PlotIdentification").text = "wdegtrhjm"
        ET.SubElement(PostalAddress_tag, "cbc:CitySubdivisionName").text = county
        ET.SubElement(PostalAddress_tag, "cbc:CityName").text = city
        ET.SubElement(PostalAddress_tag, "cbc:PostalZone").text = postal_code
        ET.SubElement(PostalAddress_tag, "cbc:CountrySubentity").text = "Saudi Arabia"

        Country_tag = ET.SubElement(PostalAddress_tag, "cac:Country")
        ET.SubElement(Country_tag, "cbc:IdentificationCode").text = "SA"

        # Tax Scheme
        PartyTaxScheme_tag = ET.SubElement(Party_tag, "cac:PartyTaxScheme")
        # <cbc:CompanyID>310306860300003</cbc:CompanyID>
        cbc_CompanyID = ET.SubElement(PartyTaxScheme_tag, "cbc:CompanyID")
        cbc_CompanyID.text = customer_doc.tax_id
        TaxScheme_tag = ET.SubElement(PartyTaxScheme_tag, "cac:TaxScheme")
        ET.SubElement(TaxScheme_tag, "cbc:ID").text = "VAT"

        # Legal Entity
        PartyLegalEntity = ET.SubElement(Party_tag, "cac:PartyLegalEntity")
        ET.SubElement(PartyLegalEntity, "cbc:RegistrationName").text = (
            "Grant Plastics Ltd."
        )

        return invoice
    

    except Exception as e:
        frappe.msgprint(frappe._(f"حدث خطأ في انشاء  {e}"))
        log_doc.coding_error = f"there is an error in add_customer_pary method in helper.py {e}"
        log_doc.save()
        return invoice


def xml_tags():
    """
    Creates an XML Invoice document with UBL, XAdES, and digital signature elements.
    """
    try:
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
        ubl_extensions = ET.SubElement(invoice, "ext:UBLExtensions")
        ubl_extension = ET.SubElement(ubl_extensions, "ext:UBLExtension")
        extension_uri = ET.SubElement(ubl_extension, "ext:ExtensionURI")
        extension_uri.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
        extension_content = ET.SubElement(ubl_extension, "ext:ExtensionContent")
        ubl_document_signatures = ET.SubElement(
            extension_content, "sig:UBLDocumentSignatures"
        )
        ubl_document_signatures.set(
            "xmlns:sig",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2",
        )
        ubl_document_signatures.set(
            "xmlns:sac",
            "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2",
        )
        ubl_document_signatures.set(
            "xmlns:sbc",
            "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2",
        )
        signature_information = ET.SubElement(
            ubl_document_signatures, "sac:SignatureInformation"
        )
        invoice_id = ET.SubElement(signature_information, CBC_ID)
        invoice_id.text = "urn:oasis:names:specification:ubl:signature:1"
        referenced_signatureid = ET.SubElement(
            signature_information, "sbc:ReferencedSignatureID"
        )
        referenced_signatureid.text = (
            "urn:oasis:names:specification:ubl:signature:Invoice"
        )
        signature = ET.SubElement(signature_information, "ds:Signature")
        signature.set("Id", "signature")
        signature.set("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
        signed_info = ET.SubElement(signature, "ds:SignedInfo")
        canonicalization_method = ET.SubElement(
            signed_info, "ds:CanonicalizationMethod"
        )
        canonicalization_method.set("Algorithm", "http://www.w3.org/2006/12/xml-c14n11")
        signature_method = ET.SubElement(signed_info, "ds:SignatureMethod")
        signature_method.set(
            "Algorithm", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        )
        reference = ET.SubElement(signed_info, "ds:Reference")
        reference.set("Id", "invoiceSignedData")
        reference.set("URI", "")
        transforms = ET.SubElement(reference, "ds:Transforms")
        transform = ET.SubElement(transforms, DS_TRANSFORM)
        transform.set("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
        xpath = ET.SubElement(transform, "ds:XPath")
        xpath.text = "not(//ancestor-or-self::ext:UBLExtensions)"
        transform2 = ET.SubElement(transforms, DS_TRANSFORM)
        transform2.set("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
        xpath2 = ET.SubElement(transform2, "ds:XPath")
        xpath2.text = "not(//ancestor-or-self::cac:Signature)"
        transform3 = ET.SubElement(transforms, DS_TRANSFORM)
        transform3.set("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
        xpath3 = ET.SubElement(transform3, "ds:XPath")
        xpath3.text = (
            "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])"
        )
        transform4 = ET.SubElement(transforms, DS_TRANSFORM)
        transform4.set("Algorithm", "http://www.w3.org/2006/12/xml-c14n11")
        diges_method = ET.SubElement(reference, "ds:DigestMethod")
        diges_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        diges_value = ET.SubElement(reference, "ds:DigestValue")
        diges_value.text = "O/vEnAxjLAlw8kQUy8nq/5n8IEZ0YeIyBFvdQA8+iFM="
        reference2 = ET.SubElement(signed_info, "ds:Reference")
        reference2.set("URI", "#xadesSignedProperties")
        reference2.set("Type", "http://www.w3.org/2000/09/xmldsig#SignatureProperties")
        digest_method1 = ET.SubElement(reference2, "ds:DigestMethod")
        digest_method1.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        digest_value1 = ET.SubElement(reference2, "ds:DigestValue")
        digest_value1.text = "YjQwZmEyMjM2NDU1YjQwNjM5MTFmYmVkO="
        signature_value = ET.SubElement(signature, "ds:SignatureValue")
        signature_value.text = "MEQCIDGBRHiPo6yhXIQ9df6pMEkufcGnoqYaS+O8Jn"
        keyinfo = ET.SubElement(signature, "ds:KeyInfo")
        x509data = ET.SubElement(keyinfo, "ds:X509Data")
        x509certificate = ET.SubElement(x509data, "ds:X509Certificate")
        x509certificate.text = (
            "MIID6TCCA5CgAwIBAgITbwAAf8tem6jngr16DwABAAB/yzAKBggqhkjOPQQ"
        )
        object_data = ET.SubElement(signature, "ds:Object")
        qualifyingproperties = ET.SubElement(object_data, "xades:QualifyingProperties")
        qualifyingproperties.set("Target", "signature")
        qualifyingproperties.set("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#")
        signedproperties = ET.SubElement(qualifyingproperties, "xades:SignedProperties")
        signedproperties.set("Id", "xadesSignedProperties")
        signedsignatureproperties = ET.SubElement(
            signedproperties, "xades:SignedSignatureProperties"
        )
        signingtime = ET.SubElement(signedsignatureproperties, "xades:SigningTime")
        signingtime.text = "2024-01-24T11:36:34Z"
        signingcertificate = ET.SubElement(
            signedsignatureproperties, "xades:SigningCertificate"
        )
        cert = ET.SubElement(signingcertificate, "xades:Cert")
        certdigest = ET.SubElement(cert, "xades:CertDigest")
        digest_method2 = ET.SubElement(certdigest, "ds:DigestMethod")
        digest_value2 = ET.SubElement(certdigest, "ds:DigestValue")
        digest_method2.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        digest_value2.text = "YTJkM2JhYTcwZTBhZTAxOGYwODMyNzY3"
        issuerserial = ET.SubElement(cert, "xades:IssuerSerial")
        x509issuername = ET.SubElement(issuerserial, "ds:X509IssuerName")
        x509serialnumber = ET.SubElement(issuerserial, "ds:X509SerialNumber")
        x509issuername.text = "CN=TSZEINVOICE-SubCA-1, DC=extgazt, DC=gov, DC=local"
        x509serialnumber.text = "2475382886904809774818644480820936050208702411"
        return invoice
    except (ET.ParseError, AttributeError, ValueError) as e:
        frappe.throw(f"Error in XML tags formation: {e}")
        return None


# help methods for salesinvoice_data()
def get_issue_time(invoice_number):
    """
    Extracts and formats the posting time of a Sales Invoice as HH:MM:SS.
    """
    doc = frappe.get_doc("Sales Invoice", invoice_number)
    time = get_time(doc.posting_time)
    issue_time = time.strftime("%H:%M:%S")  # time in format of  hour,mints,secnds
    return issue_time


def calculate_total_amountwithout_VAT(invoice_number):
    # في طريقة اسهل
    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)
        tot = 0
        for item in sales_invoice_doc.items:
            tot += abs(item.amount)

        return tot
    except Exception as e:
        frappe.log_error(
            f"Error in 'calculate_total_amountwithout_VAT' method: {e}",
            "XML Invoice Generation",
        )
        return None


def get_TaxInclusiveAmount(invoice_number):
    try:
        return round(frappe.get_doc("Sales Invoice", invoice_number).taxes[0].total, 2)
    except Exception as e:
        frappe.log_error(
            f"Error in 'get_TaxInclusiveAmount' method: {e}", "XML Invoice Generation"
        )
        return None


def calculate_AllowanceTotalAmount(invoice_number):
    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)
        total_allowance = 0
        # get allowance amount for each item in the sales invoice
        for item in sales_invoice_doc.items:
            # print("okk")
            total_allowance += item.discount_amount

        # get allowance amount on total invoice
        total_allowance += sales_invoice_doc.discount_amount
        # print("okkl")

        return total_allowance

    except Exception as e:
        frappe.log_error(
            f"Error in 'calculate_AllowanceTotalAmount' method: {e}",
            "XML Invoice Generation",
        )
        return None


def add_LegalMonetaryTotal(invoice, invoice_number):

    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)

        cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")

        cbc_LineExtensionAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:LineExtensionAmount"
        )
        cbc_LineExtensionAmount.set("currencyID", "SAR")

        # The amount is “net” without VAT
        LineExtensionAmount = calculate_total_amountwithout_VAT(
            invoice_number=invoice_number
        )
        LineExtensionAmount=abs(LineExtensionAmount)
        cbc_LineExtensionAmount.text = str(round(LineExtensionAmount, 2))
        # print("ok1")
        cbc_TaxExclusiveAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount"
        )
        cbc_TaxExclusiveAmount.set("currencyID", "SAR")
        cbc_TaxExclusiveAmount.text = str(
            round(LineExtensionAmount, 2)
        )  # itis the same as the line extension amount
        # print("ok2")

        cbc_TaxInclusiveAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount"
        )
        cbc_TaxInclusiveAmount.set("currencyID", "SAR")
        cbc_TaxInclusiveAmount.text = str(
            round(abs(get_TaxInclusiveAmount(invoice_number)), 2)
        )
        # print("ok3")

        cbc_AllowanceTotalAmount = ET.SubElement(
            cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount"
        )
        cbc_AllowanceTotalAmount.set("currencyID", "SAR")
        cbc_AllowanceTotalAmount.text = str(
            round(abs(calculate_AllowanceTotalAmount(invoice_number)), 2)
        )
        # print("ok4")

        cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")
        payable = sales_invoice_doc.outstanding_amount
        cbc_PayableAmount.set("currencyID", "SAR")
        cbc_PayableAmount.text = str(round(abs(payable), 2))
        # print("ok5")

        return invoice
    except Exception as e:
        frappe.log_error(
            f"Error in 'add_LegalMonetaryTotal' method: {e}", "XML Invoice Generation"
        )
        return None


def add_invoiceLines(invoice, invoice_number,log_doc):

    count = 1
    try:
        sales_invoice_doc = frappe.get_doc("Sales Invoice", invoice_number)

        for item in sales_invoice_doc.items:
            invoice_line = ET.SubElement(invoice, "cac:InvoiceLine")

            # ID
            cbc_id = ET.SubElement(invoice_line, "cbc:ID")
            cbc_id.text = str(count)

            # InvoicedQuantity
            invoiced_quantity = ET.SubElement(invoice_line, "cbc:InvoicedQuantity")
            invoiced_quantity.set("unitCode", "Nos")
            invoiced_quantity.text = str(float(abs(item.qty)))

            # LineExtensionAmount
            line_extension = ET.SubElement(invoice_line, "cbc:LineExtensionAmount")
            line_extension.set("currencyID", "SAR")
            line_extension.text = str(round(abs(item.amount), 2))

            # TaxTotal
            tax_total = ET.SubElement(invoice_line, "cac:TaxTotal")

            tax_amount = ET.SubElement(tax_total, "cbc:TaxAmount")
            tax_amount.set("currencyID", "SAR")
            tax_amount.text = str(round(abs(item.tax_amount), 2))

            rounding_amount = ET.SubElement(tax_total, "cbc:RoundingAmount")
            rounding_amount.set("currencyID", "SAR")
            rounding_amount.text = str(
                round(abs(item.amount) + abs(item.tax_amount), 2)
            )  # You can adjust logic if needed

            # Item
            item_tag = ET.SubElement(invoice_line, "cac:Item")
            item_name = ET.SubElement(item_tag, "cbc:Name")
            item_name.text = item.item_name

            tax_category = ET.SubElement(item_tag, "cac:ClassifiedTaxCategory")

            tax_id = ET.SubElement(tax_category, "cbc:ID")
            tax_id.text = "S"  # Default to 'Z' for zero-rated

            tax_percent = ET.SubElement(tax_category, "cbc:Percent")
            tax_percent.text = str(15.00)

            tax_scheme = ET.SubElement(tax_category, "cac:TaxScheme")
            tax_scheme_id = ET.SubElement(tax_scheme, "cbc:ID")
            tax_scheme_id.text = "VAT"

            #     # Price
            price = ET.SubElement(invoice_line, "cac:Price")
            price_amount = ET.SubElement(price, "cbc:PriceAmount")
            price_amount.set("currencyID", "SAR")
            price_amount.text = str(round(abs(item.rate), 6))

            count += 1

        return invoice

    except Exception as e:
        frappe.msgprint(f"Error in add_invoiceLine: {str(e)}", "ZATCA XML Generation")
        log_doc.coding_error = f"Error in add_invoiceLine inline {count}: {str(e)}" 
        log_doc.save()
        return invoice

def generate_QR(invoice_number):
    #     "For validation of printed invoice.
    # QR code must contain:
    # - Seller VAT number
    # - Seller Name
    # - VAT Total
    # - Invoice Total (including VAT)
    # - Hash of the XML invoice
    # - Invoice issue date and time
    # - Cryptographic stamp of seller's device
    return None


def extract_QR(xml_string: str) -> str:
    namespaces = {
        "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    }

    root = ET.fromstring(xml_string)

    # Find all EmbeddedDocumentBinaryObject elements
    embedded_documents = root.findall(".//cbc:EmbeddedDocumentBinaryObject", namespaces)

    if len(embedded_documents) >= 2:
        second_embedded = embedded_documents[1]
        base64_content = second_embedded.text

        return base64_content
    else:
        raise ValueError("Less than two EmbeddedDocumentBinaryObject elements found.")


def generate_qr_image(text: str):
    # Step 1: Generate QR Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Step 2: Save QR to memory
    img_buffer = BytesIO()
    img.save(img_buffer, format="PNG")
    img_bytes = img_buffer.getvalue()
    return img_bytes


@frappe.whitelist()
def clear_invoice(doc=None,   sales_invoice_name=None,zatca_integration_type= 'simulation'):
    log_doc = frappe.new_doc("Zatca Integration Log")

    if doc:  # Triggered by on_submit hook
        sales_invoice_doc = doc
        log_doc.fired_from = "on_submit"
    elif sales_invoice_name:  # Called from client script
        sales_invoice_doc = frappe.get_doc("Sales Invoice", sales_invoice_name)
        log_doc.fired_from = "client script"
    else:
        log_doc.coding_error = (log_doc.coding_error or '') +';'+"no sales invoice provided"
        frappe.msgprint(frappe._ ("No Sales Invoice provided."))
        log_doc.save()
        return 0
    log_doc.invoice_reference = sales_invoice_doc.name
    log_doc.save()

    print('ok1')
    if sales_invoice_doc.custom_b2c:
        frappe.msgprint(frappe._( "الفواتير المبسطة لا تعمل في الوقت الحالي."))
        log_doc.coding_error = (log_doc.coding_error or '') +';'+"try to send simple invoices"
        return 0
        
    print('ok2')

    company = frappe.get_doc("Company", sales_invoice_doc.company)

    if company.name != 'شركة أماكن للتقييم العقاري':
        frappe.msgprint(f'لم يتم الربط علي شركة {company.name} بعد')
        return
    
    zatca_amaken_settings_doc = frappe.get_doc(
        "zatca amaken settings",
        {
            "company": company.name,
            "integration_type": zatca_integration_type,
            "invoice_type": "Standard Invoices",
        },
    )

    integration_type = zatca_amaken_settings_doc.integration_type
    
    log_doc.integration_type = integration_type
    print('ok3')
    print(zatca_amaken_settings_doc.name)

    
    if frappe.db.exists( "Zatca Invoice Counting Settings",  {"zatca_settings_reference": zatca_amaken_settings_doc.name},):
      
        temp_name = frappe.get_value(
        "Zatca Invoice Counting Settings",
        filters={"zatca_settings_reference": zatca_amaken_settings_doc.name}, ) 
        
        zatca_amaken_counter_settings_doc = frappe.get_doc(
            "Zatca Invoice Counting Settings",
            temp_name,
        )

    else:

        zatca_amaken_counter_settings_doc = frappe.new_doc("Zatca Invoice Counting Settings" )
        zatca_amaken_counter_settings_doc.zatca_settings_reference = zatca_amaken_settings_doc.name
 
        zatca_amaken_counter_settings_doc.company_counter_for = company.name
        zatca_amaken_counter_settings_doc.insert()

    if frappe.db.exists(
        {
            "doctype": "Sales Invoice Additional Fields",
            "name": f"{sales_invoice_doc.name}-AdditionalFields-{integration_type}",
            
        }
    ):
      
        additional_fields_doc = frappe.get_doc(
            "Sales Invoice Additional Fields",
            f"{sales_invoice_doc.name}-AdditionalFields-{integration_type}",
        )

    else:
        additional_fields_doc = frappe.new_doc("Sales Invoice Additional Fields")
        additional_fields_doc.invoice_reference = sales_invoice_doc.name
        additional_fields_doc.integration_type = integration_type
    print('ok4')

    if (
        additional_fields_doc.integration_status == "Accepted"
        or additional_fields_doc.integration_status == "Accepted with warnings"
    ):
        frappe.msgprint("الفاتورة مرسلة لهيئة الزكاة بالفعل.")
        log_doc.coding_error = "resend sended invoice"
        log_doc.save()
        return 0

    einvoice, additional_fields_doc = einvoice_generator.gen(
        doc=sales_invoice_doc,
          additional_fields_doc=additional_fields_doc,
          log_doc=log_doc,
          zatca_amaken_settings_doc=zatca_amaken_settings_doc
    )
    if einvoice is None:
        frappe.msgprint("خطأ في إنشاء فاتورة الزكاة.")
        log_doc.coding_error = "gen einvoice failed"
        log_doc.save()
        return 0
    
    invoice_hash, encoded_invoice = hasher.get_invoice_hash(
        "amakentemp_invoice.xml"
    )
    print('ok5')

    uuid = additional_fields_doc.uuid
    additional_fields_doc.save()
    print('additional_fields_doc saved')
    U = zatca_amaken_settings_doc.production_binary_security_token
    P = zatca_amaken_settings_doc.production_secret

    print(f"U: {U}")
    print(f"P: {P}")
    print(f"UUID: {uuid}")
    print(f"invoice_hash: {invoice_hash}")
    print(f"encoded_invoice: {encoded_invoice}")


    response = clearance_invoice_call(
        username=U,
        password=P,
        invoice_hash=invoice_hash,
        encoded_invoice=encoded_invoice,
        UUID=uuid,
        integration_type=integration_type,
    )
    # important if it success call and code raised error and save it in log 
    data = json.loads(response.text)
    
    log_doc.zatca_message = f'{response.status_code}  \n  {response.text}'
    log_doc.integration_type = integration_type
    log_doc.zatca_status = data["clearanceStatus"]
    log_doc.save()
    
    print('ok5')
    
    
    
    
    if response.status_code == 200 or response.status_code == 201 or response.status_code == 202:

        integration_status = (
            "Accepted" if response.status_code == 200 else "Accepted with warnings"
        )

        # Decode the Base64 string
        xml_invoice_decoded_bytes = base64.b64decode(data["clearedInvoice"])

        # Convert bytes to string (assuming UTF-8 encoding)
        xml_invoice = xml_invoice_decoded_bytes.decode("utf-8")


        
        # Find the EmbeddedDocumentBinaryObject element
        QR_code_value = extract_QR(xml_invoice)

        img_bytes = generate_qr_image(QR_code_value)
        # Step 3: Create File and attach it to the document
        # Construct the filename
        file_name = f"QR_Code_{sales_invoice_doc.name}.png"

        # Check if the file already exists
        existing_file_name = frappe.db.get_value(
            "File",
            {
                "file_name": file_name,
                "attached_to_doctype": sales_invoice_doc.doctype,
                "attached_to_name": sales_invoice_doc.name,
            },
            "name"
        )

        # If exists, delete it
        if existing_file_name:
            delete_doc("File", existing_file_name, force=1)

        saved_file = save_file(
           file_name,
            img_bytes,
            sales_invoice_doc.doctype,
            sales_invoice_doc.name,
            is_private=0,  # set to 1 if you want to keep it private
        )


        
 

        einvoice =ET.fromstring (xml_invoice)
        tree = ET.ElementTree(einvoice)

        # Save to a file
        app_path = frappe.get_app_path("zatca_amaken")
        # print(app_path)
        output_path = os.path.join(
            app_path, "zatca_help_files", "stamp_Invoice.xml"
        )

        tree.write(
            # f"{frappe.local.site}/private/files/zatca_E-invoices/final_standardinvoice.xml",
            output_path,
            encoding="utf-8",
            xml_declaration=True,
        )
        invoice_hash_after_stamp,_ = hasher.get_invoice_hash("stamp_Invoice.xml")



        additional_fields_doc.xml_invoice = xml_invoice
        additional_fields_doc.integration_status = integration_status
        additional_fields_doc.qr_code = QR_code_value
        additional_fields_doc.db_set("qr_code_attatch", saved_file.file_url)
        additional_fields_doc.xml_invoice = xml_invoice
        additional_fields_doc.integration_status = integration_status
        additional_fields_doc.qr_code = QR_code_value
        additional_fields_doc.db_set("qr_code_attatch", saved_file.file_url) 
        additional_fields_doc.integration_type = integration_type
        additional_fields_doc.zatca_settings_integration_refrance = (
            zatca_amaken_settings_doc.name)
        additional_fields_doc.invoice_hash = invoice_hash_after_stamp
        additional_fields_doc.save()

        log_doc.status = integration_status
        log_doc.invoice_additional_fields_reference = additional_fields_doc.name
        log_doc.save()

        zatca_amaken_counter_settings_doc.previous_invoice_hash = invoice_hash_after_stamp
        zatca_amaken_counter_settings_doc.invoice_counter += 1
        zatca_amaken_counter_settings_doc.save()
        
        
        def show_zatca_warnings(warnings):
            if not warnings:
                return

            message_lines = []
            for w in warnings:
                if w.get("type") == "WARNING":
                    line = f"[{w.get('code')}] \n {w.get('message')}"
                    message_lines.append(line)
            line = f"تم إرسال الفاتورة لهيئة الزكاة والضريبة والدخل بنجاح"
            message_lines.append(line)

            if message_lines:
                
                frappe.msgprint(
                    msg="<br>".join(frappe._(message_lines)),
                    title= frappe._("Warnings"),
                    indicator="orange"  # Optional: color indicator in UI
                )
        

        if data['validationResults']['warningMessages']:
            show_zatca_warnings(data['validationResults']['warningMessages'])
        else:
            frappe.msgprint(frappe._("تم إرسال الفاتورة لهيئة الزكاة والضريبة والدخل بنجاح"))


        print('ok6')

        return 1


    else:
        additional_fields_doc.integration_status = "Rejected"
        log_doc.status = "Rejected"
        frappe.msgprint('state' ,response.status_code)
        log_doc.invoice_additional_fields_reference = additional_fields_doc.name
        log_doc.save()
        additional_fields_doc.save()
         # بدل سلسلة msgprint العشوائية دي
        error_messages = [
            "الفاتورة لم ترسل للهيئة بسبب:",
            f"{response.status_code} \n {response.text}",
            "لم يؤثر ذلك على تسجيل الفاتورة في السيستم.",
            "في حالة عدم معرفة الخطأ تواصل مع المسؤول.",
        ]

            # ترجع JSON برسالة مجمعة بدل msgprint
        print('ok7')

        return {
            "status": "Rejected",
            "errors": error_messages
        }
 
    
        
   