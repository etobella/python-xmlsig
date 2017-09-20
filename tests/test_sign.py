import unittest
from os import path

from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from lxml import etree

import xmlsig
from base import parse_xml, compare, BASE_DIR


class TestSignature(unittest.TestCase):
    def test_hmac(self):
        template = parse_xml('sign-hmac-in.xml')

        # Create a signature template for RSA-SHA1 enveloped signature.
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformHmacSha1,
            ns=None
        )

        assert sign is not None

        # Add the <ds:Signature/> node to the document.
        template.append(sign)

        # Add the <ds:Reference/> node to the signature template.
        ref = xmlsig.template.add_reference(sign,
                                            xmlsig.constants.TransformSha1)
        # Add the enveloped transform descriptor.
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

        ctx = xmlsig.SignatureContext()
        ctx.private_key = b"secret"
        ctx.public_key = b"secret"

        ctx.sign(sign)
        ctx.verify(sign)
        compare('sign-hmac-out.xml', template)

    def test_sign_generated_template_pem_with_x509(self):
        """
        Should sign a file using a dynamicaly created template, key from PEM
        file and an X509 certificate.
        """

        # Load document file.
        template = parse_xml('sign-doc.xml')

        # Create a signature template for RSA-SHA1 enveloped signature.
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformRsaSha1,
            ns=None
        )

        assert sign is not None

        # Add the <ds:Signature/> node to the document.
        template.append(sign)

        # Add the <ds:Reference/> node to the signature template.
        ref = xmlsig.template.add_reference(sign,
                                            xmlsig.constants.TransformSha1)

        # Add the enveloped transform descriptor.
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

        # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
        key_info = xmlsig.template.ensure_key_info(sign)
        x509_data = xmlsig.template.add_x509_data(key_info)
        xmlsig.template.x509_data_add_certificate(x509_data)
        # Create a digital signature context (no key manager is needed).
        # Load private key (assuming that there is no password).
        with open(path.join(BASE_DIR, "keyStore.p12"), "rb") as key_file:
            key = crypto.load_pkcs12(
                key_file.read()
            )

        assert key is not None

        # Set the key on the context.
        ctx = xmlsig.SignatureContext()
        ctx.x509 = key.get_certificate().to_cryptography()
        ctx.public_key = key.get_certificate().to_cryptography().public_key()
        ctx.private_key = key.get_privatekey().to_cryptography_key()

        # Sign the template.
        ctx.sign(sign)
        ctx.verify(sign)
        # Assert the contents of the XML document against the expected result.
        compare('sign-res.xml', template)

    def tes_sign_case1(self):
        """Should sign a pre-constructed template file using a key from a PEM file."""
        root = parse_xml("sign1-in.xml")
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        self.assertIsNotNone(sign)

        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "rsakey.pem"), "rb") as key_file:
            ctx.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        ctx.key_name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key_name)

        ctx.sign(sign)
        ctx.verify(sign)
        compare('sign1-out.xml', root)

    def test_sign_case2(self):
        """Should sign a dynamicaly constructed template file using a key from a PEM file."""
        root = parse_xml("sign2-in.xml")
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformRsaSha1,
            ns=None
        )
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsig.template.add_reference(
            sign, xmlsig.constants.TransformSha1
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        ki = xmlsig.template.ensure_key_info(sign)
        xmlsig.template.add_key_name(ki)

        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "rsakey.pem"), "rb") as key_file:
            ctx.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        ctx.key_name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key_name)
        ctx.sign(sign)
        with open(path.join(BASE_DIR, "rsacert.pem"), "rb") as cert_file:
            x509 = load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )
            ctx.public_key = x509.public_key()
        ctx.verify(sign)
        compare("sign2-out.xml", root)

    def test_sign_case3(self):
        """Should sign a file using a dynamicaly created template, key from PEM and an X509 cert."""
        root = parse_xml("sign3-in.xml")
        sign = xmlsig.template.create(
            xmlsig.constants.TransformExclC14N,
            xmlsig.constants.TransformRsaSha1,
            ns=None
        )
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsig.template.add_reference(
            sign, xmlsig.constants.TransformSha1
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        ki = xmlsig.template.ensure_key_info(sign)
        xmlsig.template.x509_data_add_certificate(
            xmlsig.template.add_x509_data(ki)
        )

        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "rsakey.pem"), "rb") as key_file:
            ctx.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        ctx.key_name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key_name)
        with open(path.join(BASE_DIR, "rsacert.pem"), "rb") as cert_file:
            ctx.x509 = load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )
            ctx.public_key = ctx.x509.public_key()
        ctx.sign(sign)
        ctx.verify(sign)
        compare("sign3-out.xml", root)

    def test_sign_case4(self):
        """Should sign a file using a dynamically created template, key from PEM and an X509 cert with custom ns."""

        root = parse_xml("sign4-in.xml")
        elem_id = root.get('ID', None)
        if elem_id:
            elem_id = '#' + elem_id
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformRsaSha1,
            ns="ds"
        )
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsig.template.add_reference(
            sign, xmlsig.constants.TransformSha1, uri=elem_id
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformExclC14N)
        ki = xmlsig.template.ensure_key_info(sign)
        xmlsig.template.x509_data_add_certificate(
            xmlsig.template.add_x509_data(ki)
        )
        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "rsakey.pem"), "rb") as key_file:
            ctx.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        ctx.key_name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key_name)
        with open(path.join(BASE_DIR, "rsacert.pem"), "rb") as cert_file:
            ctx.x509 = load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )
        ctx.sign(sign)
        ctx.verify(sign)
        compare("sign4-out.xml", root)

    def test_sign_case5(self):
        """Should sign a file using a dynamicaly created template, key from PEM file and an X509 certificate."""
        root = parse_xml("sign5-in.xml")
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformRsaSha1,
            ns=None
        )
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsig.template.add_reference(
            sign, xmlsig.constants.TransformSha1
        )
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
        ki = xmlsig.template.ensure_key_info(sign)
        x509 = xmlsig.template.add_x509_data(ki)
        xmlsig.template.x509_data_add_subject_name(x509)
        xmlsig.template.x509_data_add_certificate(x509)
        xmlsig.template.x509_data_add_ski(x509)
        x509_issuer_serial = xmlsig.template.x509_data_add_issuer_serial(x509)
        xmlsig.template.x509_issuer_serial_add_issuer_name(x509_issuer_serial)
        xmlsig.template.x509_issuer_serial_add_serial_number(
            x509_issuer_serial)
        xmlsig.template.add_key_value(ki)
        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "rsakey.pem"), "rb") as key_file:
            ctx.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        ctx.key_name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key_name)
        with open(path.join(BASE_DIR, "rsacert.pem"), "rb") as cert_file:
            ctx.x509 = load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )
        ctx.sign(sign)
        ctx.verify(sign)
        compare("sign5-out.xml", root)
