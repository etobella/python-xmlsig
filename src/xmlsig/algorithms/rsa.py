# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import base64

from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .base import Algorithm
from ..ns import DSigNs
from ..utils import create_node, long_to_bytes, b64_print


class RSAAlgorithm(Algorithm):
    private_key_class = rsa.RSAPrivateKey
    public_key_class = rsa.RSAPublicKey

    @staticmethod
    def sign(data, private_key, digest):
        return private_key.sign(
            data,
            padding.PKCS1v15(),
            digest()
        )

    @staticmethod
    def verify(signature_value, data, public_key, digest):
        public_key.verify(
            base64.b64decode(signature_value),
            data,
            padding.PKCS1v15(),
            digest()
        )

    @staticmethod
    def key_value(node, public_key):
        result = create_node(
            'RSAKeyValue', node, DSigNs, '\n', '\n'
        )
        create_node(
            'Modulus',
            result,
            DSigNs,
            tail='\n',
            text=b64_print(base64.b64encode(long_to_bytes(
                public_key.public_numbers().n
            )))
        )
        create_node(
            'Exponent',
            result,
            DSigNs,
            tail='\n',
            text=base64.b64encode(long_to_bytes(public_key.public_numbers().e))
        )
        return result
