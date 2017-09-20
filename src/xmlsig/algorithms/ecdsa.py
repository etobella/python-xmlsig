# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat import primitives
from cryptography.hazmat.primitives.asymmetric import ec
import base64

from ..utils import create_node, USING_PYTHON2
from ..ns import DSigNs11


def ecdsa_sign(data, private_key, digest):
    return private_key.sign(
        data,
        ec.ECDSA(digest())
    )


def ecdsa_verify(signature_value, data, public_key, digest):
    public_key.verify(
        base64.b64decode(signature_value),
        data,
        ec.ECDSA(digest())
    )


def ecdsa_key_value(node, public_key):
    key_value = create_node(
        'ECKeyValue', node, ns=DSigNs11, tail='\n', text='\n'
    )
    if type(public_key.curve) in CURVE_OID:
        named_curve = create_node('NamedCurve', key_value, DSigNs11, '\n')
        named_curve.set('URI', CURVE_OID[type(public_key.curve)])
    create_node(
        'PublicKey',
        key_value,
        DSigNs11,
        '\n',
        base64.b64encode(public_key.public_numbers().encode_point())
    )
    return key_value

CURVE_OID = {
    ec.SECT571K1: 'urn:oid:1.3.132.0.38',
    ec.SECT409K1: 'urn:oid:1.3.132.0.36',
    ec.SECT283K1: 'urn:oid:1.3.132.0.16',
    ec.SECT233K1: 'urn:oid:1.3.132.0.26',
    ec.SECT163K1: 'urn:oid:1.3.132.0.1',
    ec.SECT571R1: 'urn:oid:1.3.132.0.39',
    ec.SECT409R1: 'urn:oid:1.3.132.0.37',
    ec.SECT283R1: 'urn:oid:1.3.132.0.17',
    ec.SECT233R1: 'urn:oid:1.3.132.0.27',
    ec.SECT163R2: 'urn:oid:1.3.132.0.15',
    ec.SECP521R1: 'urn:oid:1.3.132.0.35',
    ec.SECP384R1: 'urn:oid:1.3.132.0.34',
    ec.SECP256R1: 'urn:oid:1.2.840.10045.3.1.7',
    ec.SECP224R1: 'urn:oid:1.3.132.0.33',
    ec.SECP192R1: 'urn:oid:1.2.840.10045.3.1.1',
    ec.SECP256K1: 'urn:oid:1.3.132.0.10'
}
if USING_PYTHON2:
    OID_CURVE = {v: k for k, v in CURVE_OID.iteritems()}
else:
    OID_CURVE = {v: k for k, v in CURVE_OID.items()}

ECDSAMethod = {
    'private_key_class': ec.EllipticCurvePrivateKey,
    'public_key_class': ec.EllipticCurvePublicKey,
    'sign': ecdsa_sign,
    'verify': ecdsa_verify,
    'key_value': ecdsa_key_value
}
