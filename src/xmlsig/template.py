from lxml import etree

from .constants import *


def add_key_name(node, name=False):
    key_name = etree.SubElement(node, etree.QName(DSigNs, 'KeyName'))
    if name:
        key_name.set('Name', name)
    key_name.tail = '\n'
    return key_name


def add_key_value(node):
    key_value = etree.SubElement(node, etree.QName(DSigNs, 'KeyValue'))
    key_value.tail = '\n'
    return key_value


def add_reference(node, digest_method, id=False, uri="", type=False):
    reference = etree.SubElement(
        node.find('{' + DSigNs + '}SignedInfo'),
        etree.QName(DSigNs, 'Reference')
    )
    reference.text = '\n'
    reference.tail = '\n'
    if id:
        reference.set('Id', id)
    reference.set('URI', uri)
    if type:
        reference.set('Type', type)
    digest_method = etree.SubElement(
        reference,
        etree.QName(DSigNs, 'DigestMethod'),
        attrib={'Algorithm': digest_method}
    )
    digest_method.tail = '\n'
    digest_value = etree.SubElement(
        reference, etree.QName(DSigNs, 'DigestValue')
    )
    digest_value.tail = '\n'
    return reference


def add_transform(node, transform):
    transforms_node = node.find('ds:Transforms', namespaces=NS_MAP)
    if transforms_node is None:
        transforms_node = etree.Element(
            etree.QName(DSigNs, 'Transforms')
        )
        transforms_node.tail = '\n'
        transforms_node.text = '\n'
        node.insert(0, transforms_node)
    transform_node = etree.SubElement(
        transforms_node,
        etree.QName(DSigNs, 'Transform'),
        attrib={'Algorithm': transform}
    )
    transform_node.tail = '\n'
    return transform_node


def add_x509_data(node):
    node.text = '\n'
    data = etree.SubElement(node, etree.QName(DSigNs, 'X509Data'))
    data.tail = '\n'
    return data


def create(c14n_method=False, sign_method=False, name=False, ns='ds'):
    node = etree.Element(etree.QName(DSigNs, 'Signature'), nsmap={ns: DSigNs})
    node.text = '\n'
    if name:
        node.set('Id', name)
    signed_info = etree.SubElement(node, etree.QName(DSigNs, 'SignedInfo'))
    signed_info.text = '\n'
    signed_info.tail = '\n'
    canonicalization = etree.SubElement(
        signed_info,
        etree.QName(DSigNs, 'CanonicalizationMethod'),
        attrib={'Algorithm': c14n_method}
    )
    canonicalization.tail = '\n'
    signature_method = etree.SubElement(
        signed_info,
        etree.QName(DSigNs, 'SignatureMethod'),
        attrib={'Algorithm': sign_method}
    )
    signature_method.tail = '\n'
    value = etree.SubElement(node, etree.QName(DSigNs, 'SignatureValue'))
    value.tail = '\n'
    return node


def ensure_key_info(node, id=False):
    if node.find('{' + DSigNs + '}KeyInfo'):
        key_info = node.find('{' + DSigNs + '}KeyInfo')
    else:
        key_info = etree.Element(etree.QName(DSigNs, 'KeyInfo'))
        key_info.tail = '\n'
        node.insert(2, key_info)
    if id:
        key_info.set('Id', id)
    return key_info


def x509_data_add_certificate(node):
    node.text = '\n'
    cert = etree.SubElement(node, etree.QName(DSigNs, 'X509Certificate'))
    cert.tail = '\n'
    return cert


def x509_data_add_crl(node):
    node.text = '\n'
    crl = etree.SubElement(node, etree.QName(DSigNs, 'X509CRL'))
    crl.tail = '\n'
    return crl


def x509_data_add_issuer_serial(node):
    node.text = '\n'
    issuer = etree.SubElement(node, etree.QName(DSigNs, 'X509IssuerSerial'))
    issuer.tail = '\n'
    return issuer


def x509_data_add_ski(node):
    node.text = '\n'
    ski = etree.SubElement(node, etree.QName(DSigNs, 'X509SKI'))
    ski.tail = '\n'
    return ski


def x509_data_add_subject_name(node):
    node.text = '\n'
    subject = etree.SubElement(node, etree.QName(DSigNs, 'X509SubjectName'))
    subject.tail = '\n'
    return subject


def x509_issuer_serial_add_issuer_name(node):
    node.text = '\n'
    name = etree.SubElement(node, etree.QName(DSigNs, 'X509IssuerName'))
    name.tail = '\n'
    return name


def x509_issuer_serial_add_serial_number(node):
    node.text = '\n'
    number = etree.SubElement(node, etree.QName(DSigNs, 'X509SerialNumber'))
    number.tail = '\n'
    return number
