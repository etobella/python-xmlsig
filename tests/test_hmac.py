import unittest
from os import path

from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

import xmlsig
from .base import parse_xml, compare, BASE_DIR


class TestSignature(unittest.TestCase):
    def test_hmac(self):
        template = parse_xml('data/sign-hmac-in.xml')

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
        compare('data/sign-hmac-out.xml', template)
