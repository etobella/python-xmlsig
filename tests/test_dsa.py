import unittest
from os import path

from cryptography.hazmat.primitives.serialization import pkcs12

import xmlsig

from .base import BASE_DIR, parse_xml


class TestDSASignature(unittest.TestCase):
    def test_dsa(self):
        root = parse_xml("data/sign-dsa-in.xml")
        sign = root.xpath("//ds:Signature", namespaces={"ds": xmlsig.constants.DSigNs})[
            0
        ]
        self.assertIsNotNone(sign)
        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "data/dsacred.p12"), "rb") as key_file:
            ctx.load_pkcs12(pkcs12.load_key_and_certificates(key_file.read(), None))
        ctx.sign(sign)
        ctx.verify(sign)

    def test_verify(self):
        ctx = xmlsig.SignatureContext()
        root = parse_xml("data/sign-dsa-out.xml")
        sign = root.xpath("//ds:Signature", namespaces={"ds": xmlsig.constants.DSigNs})[
            0
        ]
        ctx.verify(sign)
