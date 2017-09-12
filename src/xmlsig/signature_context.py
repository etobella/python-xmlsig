import base64
import hashlib
import struct
import sys

from OpenSSL import crypto
from lxml import etree

from . import constants

USING_PYTHON2 = True if sys.version_info < (3, 0) else False
b64_intro = 76


def b64_print(s):
    if USING_PYTHON2:
        string = str(s)
    else:
        string = str(s, 'utf8')
    return '\n' + ('\n'.join(
        string[pos:pos + b64_intro] for pos in range(0, len(string), b64_intro)
    )) + '\n'


def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.
    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b''
    if USING_PYTHON2:
        n = long(n)  # noqa
    pack = struct.pack
    while n > 0:
        s = pack(b'>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b'\000'[0]:
            break
    else:
        # only happens when n == 0
        s = b'\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b'\000' + s
    return s


class SignatureContext:
    def __init__(self, key=False):
        self.key = key

    def sign(self, node):
        signed_info = node.find('ds:SignedInfo', namespaces=constants.NS_MAP)
        signature_method = signed_info.find('ds:SignatureMethod',
                                            namespaces=constants.NS_MAP).get(
            'Algorithm')
        key_info = node.find('ds:KeyInfo', namespaces=constants.NS_MAP)
        self.fill_key_info(key_info, signature_method)
        self.fill_signed_info(signed_info)
        self.calculate_signature(node)

    def fill_key_info(self, key_info, signature_method):
        x509_data = key_info.find('ds:X509Data', namespaces=constants.NS_MAP)
        if x509_data is not None:
            self.fill_x509_data(x509_data)
        key_value = key_info.find('ds:KeyValue', namespaces=constants.NS_MAP)
        if key_value is not None:
            key_value.text='\n'
            if constants.TransformUsageSignatureMethod[signature_method][
                'key_value'
            ] == 'rsa':
                rsa_key_value = etree.SubElement(
                    key_value, etree.QName(constants.DSigNs, 'RSAKeyValue')
                )
                rsa_key_value.tail = '\n'
                rsa_key_value.text = '\n'
                s = base64.b64encode(
                    long_to_bytes(
                        self.key.get_privatekey().to_cryptography_key(
                        ).public_key().public_numbers().n
                    )
                )
                modulus = etree.SubElement(
                    rsa_key_value, etree.QName(constants.DSigNs, 'Modulus')
                )
                modulus.tail = '\n'
                modulus.text = b64_print(s)
                exponent = etree.SubElement(
                    rsa_key_value,
                    etree.QName(constants.DSigNs, 'Exponent')
                )
                exponent.tail = '\n'
                exponent.text = base64.b64encode(
                    long_to_bytes(
                        self.key.get_privatekey().to_cryptography_key(
                        ).public_key().public_numbers().e
                    )
                )
        return

    def fill_x509_data(self, x509_data):
        x509_issuer_serial = x509_data.find(
            'ds:X509IssuerSerial', namespaces=constants.NS_MAP
        )
        if x509_issuer_serial is not None:
            self.fill_x509_issuer_name(x509_issuer_serial)
        x509_ski = x509_data.find('ds:X509SKI', namespaces=constants.NS_MAP)
        if x509_ski is not None:
            x509_ski.text = self.key.get_certificate(
            ).extensions.get_extension_for_oid(
                crypto.x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
        x509_certificate = x509_data.find(
            'ds:X509Certificate', namespaces=constants.NS_MAP
        )
        if x509_certificate is not None:
            s = base64.b64encode(
                crypto.dump_certificate(
                    crypto.FILETYPE_ASN1, self.key.get_certificate()
                )
            )
            x509_certificate.text = b64_print(s)

    def fill_x509_issuer_name(self, x509_issuer_serial):
        x509_issuer_name = x509_issuer_serial.find(
            'ds:X509IssuerName', namespaces=constants.NS_MAP
        )
        if x509_issuer_name:
            issuer = ''
            comps = self.key.get_certificate().get_issuer().get_components()
            for entry in comps:
                issuer = entry[0] + '=' + entry[1] + (
                    (',' + issuer) if len(issuer) > 0 else ''
                )
                x509_issuer_name.text = issuer
        x509_issuer_number = x509_issuer_serial.find(
            'ds:X509SerialNumber', namespaces=constants.NS_MAP
        )
        if x509_issuer_number:
            x509_issuer_number.text = self.key.get_certificate().get_serial()

    def fill_signed_info(self, signed_info):
        canonicalization_method = signed_info.find(
            'ds:CanonicalizationMethod', namespaces=constants.NS_MAP
        ).get('Algorithm')
        for reference in signed_info.findall(
                'ds:Reference', namespaces=constants.NS_MAP
        ):
            self.calculate_reference(canonicalization_method, reference, True)
        return

    def verify(self, node):
        signed_info = node.find('ds:SignedInfo', namespaces=constants.NS_MAP)
        canonicalization_method = signed_info.find(
            'ds:CanonicalizationMethod', namespaces=constants.NS_MAP
        ).get('Algorithm')
        for reference in signed_info.findall(
                'ds:Reference', namespaces=constants.NS_MAP
        ):
            if not self.calculate_reference(
                    canonicalization_method, reference, False
            ):
                raise Exception(
                    'Reference with URI:"' +
                    reference.get("URI") +
                    '" failed'
                )
        return self.calculate_signature(node, False)

    def transform(self, transform, node, canonicalization_method):
        method = transform.get('Algorithm')
        if method not in constants.TransformUsageDSigTransform:
            raise Exception('Method not allowed')
        if method == constants.TransformEnveloped:
            tree = transform.getroottree()
            root = etree.fromstring(node)
            map = {}
            map.update(transform.nsmap)
            map.update(root.nsmap)
            signature = root.xpath(
                tree.getpath(
                    transform.getparent().getparent().getparent().getparent()),
                namespaces=map)[0]
            root.remove(signature)
            return self.canonicalization(canonicalization_method, root)
        raise Exception('Method not found')

    def canonicalization(self, method, node):
        if method not in constants.TransformUsageC14NMethod:
            raise Exception('Method not allowed: ' + method)
        vars = constants.TransformUsageC14NMethod[method]
        return etree.tostring(
            node,
            method=vars['method'],
            with_comments=vars['comments'],
            exclusive=vars['exclusive']
        )

    def digest(self, method, object):
        if method not in constants.TransformUsageDigestMethod:
            raise Exception('Method not allowed')
        lib = hashlib.new(constants.TransformUsageDigestMethod[method])
        lib.update(object)
        return base64.b64encode(lib.digest())

    def get_uri(self, uri, reference, canonicalization_method):
        if uri == "":
            return self.canonicalization(
                canonicalization_method, reference.getroottree()
            )
        if uri.startswith("#"):
            xpath_query = "//*[@*[local-name() = '{}']=$uri]".format('Id')
            results = reference.getroottree().xpath(
                xpath_query, uri=uri.lstrip("#")
            )
            if len(results) > 1:
                raise Exception(
                    "Ambiguous reference URI {} resolved to {} nodes".format(
                        uri, len(results)))
            elif len(results) == 1:
                return self.canonicalization(
                    canonicalization_method, results[0]
                )
        raise Exception('URI cannot be readed')

    def calculate_reference(self, canonicalization_method, reference,
                            sign=True):
        node = self.get_uri(
            reference.get('URI', ''), reference, canonicalization_method
        )
        transforms = reference.find(
            'ds:Transforms', namespaces=constants.NS_MAP
        )
        if transforms is not None:
            for transform in transforms.findall(
                    'ds:Transform', namespaces=constants.NS_MAP
            ):
                node = self.transform(transform, node, canonicalization_method)
        digest_value = self.digest(
            reference.find(
                'ds:DigestMethod', namespaces=constants.NS_MAP
            ).get('Algorithm'), node
        )
        if not sign:
            return digest_value == reference.find(
                'ds:DigestValue', namespaces=constants.NS_MAP
            ).text
        reference.find(
            'ds:DigestValue', namespaces=constants.NS_MAP
        ).text = digest_value

    def calculate_signature(self, node, sign=True):
        signed_info_xml = node.find('ds:SignedInfo',
                                    namespaces=constants.NS_MAP)
        canonicalization_method = signed_info_xml.find(
            'ds:CanonicalizationMethod',
            namespaces=constants.NS_MAP).get('Algorithm')
        signature_method = signed_info_xml.find('ds:SignatureMethod',
                                                namespaces=constants.NS_MAP).get(
            'Algorithm')
        if signature_method not in constants.TransformUsageSignatureMethod:
            raise Exception('Method not accepted')
        signed_info = self.canonicalization(canonicalization_method,
                                            signed_info_xml)
        if not sign:
            signature_value = node.find('ds:SignatureValue',
                                        namespaces=constants.NS_MAP).text
            x509 = crypto.load_certificate(
                crypto.FILETYPE_ASN1,
                base64.b64decode(
                    node.find(
                        'ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                        namespaces=constants.NS_MAP
                    ).text
                )
            )
            return crypto.verify(
                x509,
                base64.b64decode(signature_value),
                signed_info,
                constants.TransformUsageSignatureMethod[signature_method][
                    'digest']
            )
        else:
            s = base64.b64encode(
                crypto.sign(
                    self.key.get_privatekey(),
                    signed_info,
                    constants.TransformUsageSignatureMethod[signature_method][
                        'digest'])
            )
            node.find(
                'ds:SignatureValue', namespaces=constants.NS_MAP
            ).text = b64_print(s)
