# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat import primitives
from ..utils import create_node, long_to_bytes, b64_print
from ..ns import DSigNs
import base64


def rsa_sign(data, private_key, digest):
    return private_key.sign(
        data,
        primitives.asymmetric.padding.PKCS1v15(),
        digest()
    )


def rsa_verify(signature_value, data, public_key, digest):
    public_key.verify(
        base64.b64decode(signature_value),
        data,
        primitives.asymmetric.padding.PKCS1v15(),
        digest()
    )


def rsa_key_value(node, public_key):
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


RSAMethod = {
    'private_key_class': primitives.asymmetric.rsa.RSAPrivateKey,
    'public_key_class': primitives.asymmetric.rsa.RSAPublicKey,
    'sign': rsa_sign,
    'verify': rsa_verify,
    'key_value': rsa_key_value
}
