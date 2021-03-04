import base64
import unittest

import xmlsig
from lxml import etree

from .base import compare, parse_xml


class TestSignature(unittest.TestCase):
    def test_hmac(self):
        template = parse_xml("data/sign-hmac-in.xml")

        # Create a signature template for RSA-SHA1 enveloped signature.
        sign = xmlsig.template.create(
            c14n_method=xmlsig.constants.TransformExclC14N,
            sign_method=xmlsig.constants.TransformHmacSha1,
            ns="ds",
        )

        assert sign is not None

        # Add the <ds:Signature/> node to the document.
        template.append(sign)

        # Add the <ds:Reference/> node to the signature template.
        ref = xmlsig.template.add_reference(sign, xmlsig.constants.TransformSha1)
        # Add the enveloped transform descriptor.
        xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

        ref_obj = xmlsig.template.add_reference(
            sign, xmlsig.constants.TransformSha1, uri="#R1"
        )
        xmlsig.template.add_transform(ref_obj, xmlsig.constants.TransformBase64)
        obj = etree.SubElement(sign, etree.QName(xmlsig.constants.DSigNs, "Object"))
        obj.set("Id", "R1")
        obj.text = base64.b64encode(b"Some Text")
        ctx = xmlsig.SignatureContext()
        ctx.private_key = b"secret"

        ctx.sign(sign)
        ctx.verify(sign)
        compare("data/sign-hmac-out.xml", template)
