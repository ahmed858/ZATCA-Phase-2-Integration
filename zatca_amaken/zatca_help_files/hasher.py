import hashlib
import base64
from lxml import etree
import xml.etree.ElementTree as ET
import os


def get_uuid_from_xml(filename: str) -> str:
    """Extracts the UUID from a ZATCA-compliant XML invoice file."""
    # Register the namespace if necessary
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    tree = ET.parse(file_path)
    root = tree.getroot()

    namespaces = {
        "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        "default": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    }

    uuid_element = root.find("cbc:UUID", namespaces)
    if uuid_element is not None:
        return uuid_element.text
    else:
        raise ValueError("UUID element not found in the XML file.")


def get_invoice_hash(filename: str) -> str:
    """
    Canonicalizes XML from file, hashes it with SHA-256, and returns Base64-encoded hash.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    with open(file_path, "rb") as f:
        tree = etree.parse(f)
        canonical_xml = etree.tostring(tree, method="c14n")  # Canonical XML (C14N)

    encoded_invoice = base64.b64encode(canonical_xml).decode("utf-8")

    sha256_hash = hashlib.sha256(canonical_xml).digest()
    base64_encoded_hash = base64.b64encode(sha256_hash).decode("utf-8")

    return base64_encoded_hash, encoded_invoice


def string_to_invoice_hash(text: str) -> str:
    """
    Canonicalizes XML from string, hashes it with SHA-256, and returns Base64-encoded hash.
    """
    # تحويل النص إلى شجرة XML
    tree = etree.fromstring(text.encode("utf-8"))

    # تحويل الشجرة إلى XML بشكل Canonical (C14N)
    canonical_xml = etree.tostring(tree, method="c14n")

    # حساب الهاش باستخدام SHA-256
    hash_object = hashlib.sha256(canonical_xml)
    hash_digest = hash_object.digest()

    # تحويل الهاش إلى Base64
    base64_hash = base64.b64encode(hash_digest).decode("utf-8")

    return base64_hash
