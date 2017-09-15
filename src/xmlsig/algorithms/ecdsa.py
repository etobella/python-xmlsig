# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat import primitives
from cryptography.hazmat.primitives.asymmetric import ec
import base64


def ecdsa_sign(data, private_key, digest):
    return private_key.sign(
        data,
        primitives.asymmetric.ec.ECDSA(digest())
    )


def ecdsa_verify(signature_value, data, public_key, digest):
    public_key.verify(
        base64.b64decode(signature_value),
        data,
        primitives.asymmetric.ec.ECDSA(digest())
    )


def ecdsa_key_value(node, public_key):
    return None


ECDSAMethod = {
    'private_key_class': primitives.asymmetric.ec.EllipticCurvePrivateKey,
    'public_key_class': primitives.asymmetric.ec.EllipticCurvePublicKey,
    'sign': ecdsa_sign,
    'verify': ecdsa_verify,
    'key_value': ecdsa_key_value
}
