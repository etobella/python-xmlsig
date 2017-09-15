# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat import primitives
from ..utils import create_node, long_to_bytes, b64_print
from ..ns import DSigNs
import base64




def i2osp(x, xLen):
        if x >= 256^xLen:
            raise ValueError("integer too large")
        digits = []

        while x:
            digits.append(int(x % 256))
            x //= 256
        for i in range(xLen - len(digits)):
            digits.append(0)
        return digits[::-1]

def os2ip(X):
        xLen = len(X)
        X = X[::-1]
        x = 0
        for i in range(xLen):
            x += X[i] * 256^i
        return x




def dsa_sign(data, private_key, digest):
    r,s = primitives.asymmetric.utils.decode_dss_signature(private_key.sign(
        data,
        digest()
    ))
    print i2osp(r, 20)
    print i2osp(2, 20)
    return i2osp(r, 20) + i2osp(s, 20)


def dsa_verify(signature_value, data, public_key, digest):
    public_key.verify(
        base64.b64decode(signature_value),
        data,
        digest()
    )


def dsa_key_value(node, public_key):
    result = create_node(
        'DSAKeyValue', node, DSigNs, '\n', '\n'
    )
    public_numbers = public_key.public_numbers()
    if public_numbers.parameter_numbers.p is not None:
        create_node(
            'P',
            result,
            DSigNs,
            tail='\n',
            text='\n' + b64_print(base64.b64encode(long_to_bytes(
                public_numbers.parameter_numbers.p
            ))) + '\n'
        )
    if public_numbers.parameter_numbers.q is not None:
        create_node(
            'Q',
            result,
            DSigNs,
            tail='\n',
            text='\n' + b64_print(base64.b64encode(long_to_bytes(
                public_numbers.parameter_numbers.q
            ))) + '\n'
        )
    if public_numbers.parameter_numbers.g is not None:
        create_node(
            'G',
            result,
            DSigNs,
            tail='\n',
            text='\n' + b64_print(base64.b64encode(long_to_bytes(
                public_numbers.parameter_numbers.g
            ))) + '\n'
        )
    if public_numbers.y is not None:
        create_node(
            'Y',
            result,
            DSigNs,
            tail='\n',
            text='\n' + b64_print(base64.b64encode(long_to_bytes(
                public_numbers.y
            ))) + '\n'
        )
    return result


DSAMethod = {
    'private_key_class': primitives.asymmetric.dsa.DSAPrivateKey,
    'public_key_class': primitives.asymmetric.dsa.DSAPublicKey,
    'sign': dsa_sign,
    'verify': dsa_verify,
    'key_value': dsa_key_value
}
