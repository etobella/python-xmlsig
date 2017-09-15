import base64
import hashlib

from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from lxml import etree

from . import constants
from .utils import long_to_bytes, b64_print, create_node, get_rdns_name


class SignatureContext:
    def __init__(self):
        self.x509 = None
        self.crl = None
        self.private_key = None
        self.public_key = None
        self.key_name = ""

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
        key_name = key_info.find('ds:KeyName', namespaces=constants.NS_MAP)
        if key_name is not None:
            key_name.text = self.key_name
        key_value = key_info.find('ds:KeyValue', namespaces=constants.NS_MAP)
        if key_value is not None:
            key_value.text = '\n'
            public_key_class = constants.TransformUsageSignatureMethod[
                signature_method
            ]['public_key_class']
            if not isinstance(self.public_key, public_key_class):
                raise Exception('Key not compatible with signature method')
            if isinstance(self.public_key, asymmetric.rsa.RSAPublicKey):
                rsa_key_value = create_node(
                    'RSAKeyValue', key_value, constants.DSigNs, '\n', '\n'
                )
                create_node(
                    'Modulus',
                    rsa_key_value,
                    constants.DSigNs,
                    tail='\n',
                    text=b64_print(base64.b64encode(long_to_bytes(
                        self.public_key.public_numbers().n
                    )))
                )
                create_node(
                    'Exponent',
                    rsa_key_value,
                    constants.DSigNs,
                    tail='\n',
                    text=base64.b64encode(long_to_bytes(
                        self.private_key.public_key().public_numbers().e
                    ))
                )
        return

    def fill_x509_data(self, x509_data):
        x509_issuer_serial = x509_data.find(
            'ds:X509IssuerSerial', namespaces=constants.NS_MAP
        )
        if x509_issuer_serial is not None:
            self.fill_x509_issuer_name(x509_issuer_serial)

        x509_crl = x509_data.find('ds:X509CRL', namespaces=constants.NS_MAP)
        if x509_crl is not None and self.crl is not None:
            x509_data.text = base64.b64encode(
                self.crl.public_bytes(serialization.Encoding.DER)
            )
        x509_subject = x509_data.find(
            'ds:X509SubjectName', namespaces=constants.NS_MAP
        )
        if x509_subject is not None:
            x509_subject.text = get_rdns_name(self.x509.subject.rdns)
        x509_ski = x509_data.find('ds:X509SKI', namespaces=constants.NS_MAP)
        if x509_ski is not None:
            x509_ski.text = base64.b64encode(
                self.x509.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value.digest)
        x509_certificate = x509_data.find(
            'ds:X509Certificate', namespaces=constants.NS_MAP
        )
        if x509_certificate is not None:
            s = base64.b64encode(
                self.x509.public_bytes(encoding=serialization.Encoding.DER)
            )
            x509_certificate.text = b64_print(s)

    def fill_x509_issuer_name(self, x509_issuer_serial):
        x509_issuer_name = x509_issuer_serial.find(
            'ds:X509IssuerName', namespaces=constants.NS_MAP
        )
        if x509_issuer_name is not None:
            x509_issuer_name.text = get_rdns_name(self.x509.issuer.rdns)
        x509_issuer_number = x509_issuer_serial.find(
            'ds:X509SerialNumber', namespaces=constants.NS_MAP
        )
        if x509_issuer_number is not None:
            x509_issuer_number.text = str(self.x509.serial_number)

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
                    reference.get("URI", '') +
                    '" failed'
                )
        return self.calculate_signature(node, False)

    def transform(self, transform, node, canonicalization_method):
        method = transform.get('Algorithm')
        if method not in constants.TransformUsageDSigTransform:
            raise Exception('Method not allowed')
        if method in constants.TransformUsageC14NMethod:
            return self.canonicalization(method, etree.fromstring(node))
        if method == constants.TransformEnveloped:
            tree = transform.getroottree()
            root = etree.fromstring(node)
            signature = root.find(
                tree.getelementpath(
                    transform.getparent().getparent().getparent().getparent()
                )
            )
            root.remove(signature)
            return etree.tostring(root)
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
            return etree.tostring(reference.getroottree())
        if uri.startswith("#"):
            xpath_query = "//*[@*[local-name() = '{}']=$uri]".format('ID')
            results = reference.getroottree().xpath(
                xpath_query, uri=uri.lstrip("#")
            )
            if len(results) > 1:
                raise Exception(
                    "Ambiguous reference URI {} resolved to {} nodes".format(
                        uri, len(results)))
            elif len(results) == 1:
                return etree.tostring(results[0])
        raise Exception('URI cannot be readed')

    def get_public_key(self, sign):
        x509_certificate = sign.find(
            'ds:KeyInfo/ds:X509Data/ds:X509Certificate',
            namespaces={'ds': constants.DSigNs}
        )
        if x509_certificate is not None:
            return load_der_x509_certificate(
                base64.b64decode(x509_certificate.text),
                default_backend()
            ).public_key()
        return self.public_key

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
            return digest_value.decode() == reference.find(
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
        digest = constants.TransformUsageSignatureMethod[signature_method][
            'digest']
        if not sign:
            signature_value = node.find('ds:SignatureValue',
                                        namespaces=constants.NS_MAP).text
            public_key = self.get_public_key(node)

            public_key.verify(
                base64.b64decode(signature_value),
                signed_info,
                asymmetric.padding.PKCS1v15(),
                digest()
            )
        else:
            s = base64.b64encode(
                self.private_key.sign(
                    signed_info,
                    asymmetric.padding.PKCS1v15(),
                    digest()
                )
            )
            node.find(
                'ds:SignatureValue', namespaces=constants.NS_MAP
            ).text = b64_print(s)
