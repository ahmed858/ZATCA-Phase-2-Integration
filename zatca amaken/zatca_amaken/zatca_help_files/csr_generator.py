import os
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

import frappe
import asn1


def generate_Private_Key_pem():

    private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # private_key = serialization.load_pem_private_key(
    #     private_key_pem, password=None, backend=default_backend()
    # )
    # return this
    # return private_key_pem.decode()


def generate_Public_Key(private_key_pem):
    public_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    ).public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem.decode()


def encode_customoid(custom_string):
    """Encoding of a custom string"""
    # Create an encoder
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(custom_string, asn1.Numbers.UTF8String)
    return encoder.output()


@frappe.whitelist()
def create_csr(ZATCA_settings_name):
    try:
        ZATCA_settings_doc = frappe.get_doc(
            "zatca amaken settings", ZATCA_settings_name
        )
        # private_key_pem
        private_key_pem = generate_Private_Key_pem()
        ZATCA_settings_doc.private_key = private_key_pem.decode()

        public_key = generate_Public_Key(private_key_pem)
        ZATCA_settings_doc.public_key = public_key

        custom_oid_string = "1.3.6.1.4.1.311.20.2"
        oid = ObjectIdentifier(custom_oid_string)

        portal_type = ZATCA_settings_doc.integration_type
        if portal_type == "sandbox":
            customoid = encode_customoid("TESTZATCA-Code-Signing")
        elif portal_type == "simulation":
            customoid = encode_customoid("PREZATCA-Code-Signing")
        else:
            customoid = encode_customoid("ZATCA-Code-Signing")
        type = ZATCA_settings_doc.invoice_type
        invoices_type = "1000"
        if type == "Standard Invoices":
            invoices_type = "1000"
        elif type == "Simplified Invoices":
            invoices_type = "0100"
        else:
            invoices_type = "1100"
        custom_extension = x509.extensions.UnrecognizedExtension(oid, customoid)

        dn = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, ZATCA_settings_doc.country_name
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    ZATCA_settings_doc.organization_unit_name,
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, ZATCA_settings_doc.organization_name
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, ZATCA_settings_doc.common_name),
            ]
        )

        alt_name = x509.SubjectAlternativeName(
            [
                x509.DirectoryName(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.SURNAME, ZATCA_settings_doc.serial_number
                            ),
                            x509.NameAttribute(
                                NameOID.USER_ID,
                                ZATCA_settings_doc.organization_identifier,
                            ),
                            x509.NameAttribute(NameOID.TITLE, invoices_type),
                            x509.NameAttribute(
                                ObjectIdentifier("2.5.4.26"),
                                ZATCA_settings_doc.location_address,
                            ),
                            x509.NameAttribute(
                                NameOID.BUSINESS_CATEGORY,
                                ZATCA_settings_doc.business_category,
                            ),
                        ]
                    )
                ),
            ]
        )

        private_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(dn)
            .add_extension(custom_extension, critical=False)
            .add_extension(alt_name, critical=False)
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        mycsr = csr.public_bytes(serialization.Encoding.PEM)
        base64_encoded_csr = base64.b64encode(mycsr).decode("utf-8")
        ZATCA_settings_doc.csr = base64_encoded_csr
        ZATCA_settings_doc.save(ignore_permissions=True)

        frappe.msgprint(f"CSR Generated Successfully: {ZATCA_settings_doc.csr}")
        return 1

    except Exception as e:
        frappe.throw(f"Error generating CSR: {str(e)}")
        return -1
