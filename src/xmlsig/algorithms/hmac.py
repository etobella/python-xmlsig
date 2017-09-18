# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat import primitives, backends
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
import base64


def hmac_sign(data, private_key, digest):
    h = hmac.HMAC(
        private_key,
        digest(),
        backend=backends.default_backend()
    )
    h.update(data)
    return h.finalize()


def hmac_verify(signature_value, data, public_key, digest):
    h = hmac.HMAC(
        public_key, digest(), backend=backends.default_backend()
    )
    h.update(data)
    h.verify(base64.b64decode(signature_value))


def hmac_key_value(node, public_key):
    return None


HMACMethod = {
    'private_key_class': hmac.HMAC,
    'public_key_class': hmac.HMAC,
    'sign': hmac_sign,
    'verify': hmac_verify,
    'key_value': hmac_key_value
}
