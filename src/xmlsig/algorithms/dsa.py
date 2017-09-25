# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import struct
from base64 import b64decode, b64encode

from asn1crypto.algos import DSASignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from xmlsig.algorithms.base import Algorithm
from xmlsig.ns import NS_MAP, DSigNs
from xmlsig.utils import USING_PYTHON2, b64_print, create_node, long_to_bytes


def i2osp(x, x_len):
    if x >= pow(256, x_len):
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for _i in range(x_len - len(digits)):
        digits.append(0)
    return bytearray(digits[::-1])


def os2ip(arr):
    x_len = len(arr)
    x = 0
    for i in range(x_len):
        if USING_PYTHON2:
            val = struct.unpack("B", arr[i])[0]
        else:
            val = arr[i]
        x = x + (val * pow(256, x_len - i - 1))
    return x


def to_int(element):
    if USING_PYTHON2:
        return struct.unpack("B", element)[0]
    return element


class DSAAlgorithm(Algorithm):
    private_key_class = dsa.DSAPrivateKey
    public_key_class = dsa.DSAPublicKey

    @staticmethod
    def sign(data, private_key, digest):
        return DSASignature.load(private_key.sign(data, digest())).to_p1363()

    @staticmethod
    def verify(signature_value, data, public_key, digest):
        public_key.verify(
            DSASignature.from_p1363(b64decode(signature_value)).dump(), data, digest()
        )

    @staticmethod
    def key_value(node, public_key):
        result = create_node("DSAKeyValue", node, DSigNs, "\n", "\n")
        public_numbers = public_key.public_numbers()
        if public_numbers.parameter_numbers.p is not None:
            create_node(
                "P",
                result,
                DSigNs,
                tail="\n",
                text="\n"
                + b64_print(
                    b64encode(long_to_bytes(public_numbers.parameter_numbers.p))
                )
                + "\n",
            )
        if public_numbers.parameter_numbers.q is not None:
            create_node(
                "Q",
                result,
                DSigNs,
                tail="\n",
                text="\n"
                + b64_print(
                    b64encode(long_to_bytes(public_numbers.parameter_numbers.q))
                )
                + "\n",
            )
        if public_numbers.parameter_numbers.g is not None:
            create_node(
                "G",
                result,
                DSigNs,
                tail="\n",
                text="\n"
                + b64_print(
                    b64encode(long_to_bytes(public_numbers.parameter_numbers.g))
                )
                + "\n",
            )
        if public_numbers.y is not None:
            create_node(
                "Y",
                result,
                DSigNs,
                tail="\n",
                text="\n"
                + b64_print(b64encode(long_to_bytes(public_numbers.y)))
                + "\n",
            )
        return result

    @staticmethod
    def get_public_key(key_info, context):
        key = key_info.find("ds:KeyInfo/ds:KeyValue/ds:DSAKeyValue", namespaces=NS_MAP)
        if key is not None:
            p = os2ip(b64decode(key.find("ds:P", namespaces=NS_MAP).text))
            q = os2ip(b64decode(key.find("ds:Q", namespaces=NS_MAP).text))
            g = os2ip(b64decode(key.find("ds:G", namespaces=NS_MAP).text))
            y = os2ip(b64decode(key.find("ds:Y", namespaces=NS_MAP).text))
            return dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key(
                default_backend()
            )
        return super(DSAAlgorithm, DSAAlgorithm).get_public_key(key_info, context)
