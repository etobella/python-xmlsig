# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import array
import base64
import struct
from cryptography.hazmat import primitives

from ..ns import DSigNs
from ..utils import create_node, long_to_bytes, b64_print, USING_PYTHON2


def i2osp(x, x_len):
    if x >= pow(256, x_len):
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(x_len - len(digits)):
        digits.append(0)
    return digits


def os2ip(arr):
    x_len = len(arr)
    x = 0
    for i in range(x_len):
        if USING_PYTHON2:
            val = struct.unpack('B', arr[i])[0]
        else:
            val = arr[i]
        x = x + (val * pow(256, x_len - i - 1))
    return x


def dsa_sign(data, private_key, digest):
    signature = private_key.sign(
        data,
        digest()
    )
    r, s = primitives.asymmetric.utils.decode_dss_signature(signature)
    print(base64.b64encode(bytearray(long_to_bytes(r, 20) + long_to_bytes(s, 20))))
    return bytearray(long_to_bytes(r, 32) + long_to_bytes(s, 32))


def dsa_verify(signature_value, data, public_key, digest):
    decoded = base64.b64decode(signature_value)
    r = os2ip(decoded[:20])
    s = os2ip(decoded[20:])
    public_key.verify(
        primitives.asymmetric.utils.encode_dss_signature(r, s),
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
