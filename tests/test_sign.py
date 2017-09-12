from os import path
from OpenSSL import crypto
import xmlsig
from .base import parse_xml, compare, BASE_DIR


def test_sign_generated_template_pem_with_x509():
    """
    Should sign a file using a dynamicaly created template, key from PEM
    file and an X509 certificate.
    """

    # Load document file.
    template = parse_xml('sign-doc.xml')

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsig.template.create(
        c14n_method=xmlsig.constants.TransformExclC14N,
        sign_method=xmlsig.constants.TransformRsaSha1,
        ns=None
    )

    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsig.template.add_reference(signature_node, xmlsig.constants.TransformSha1)

    # Add the enveloped transform descriptor.
    xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

    # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
    key_info = xmlsig.template.ensure_key_info(signature_node)
    x509_data = xmlsig.template.add_x509_data(key_info)
    xmlsig.template.x509_data_add_certificate(x509_data)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsig.SignatureContext()

    # Load private key (assuming that there is no password).
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = crypto.load_pkcs12(
        open(path.join(BASE_DIR, "keyStore.p12"), "rb").read()
    )

    assert key is not None

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None

    # Sign the template.
    ctx.sign(signature_node)
    # Assert the contents of the XML document against the expected result.
    compare('sign-res.xml', template)

test_sign_generated_template_pem_with_x509()