# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from cryptography.hazmat.primitives import hashes

from .algorithms import RSAAlgorithm, HMACAlgorithm
from .ns import DSigNs, DSigNs11, NS_MAP

ID_ATTR = 'Id'

TransformInclC14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
TransformInclC14NWithComments = 'http://www.w3.org/TR/2001/' \
                                'REC-xml-c14n-20010315#WithComments'
TransformInclC14N11 = ''
TransformInclC14N11WithComments = ''
TransformExclC14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
TransformExclC14NWithComments = 'http://www.w3.org/2001/10/xml-exc-c14n#' \
                                'WithComments'
TransformEnveloped = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
TransformXPath = 'http://www.w3.org/TR/1999/REC-xpath-19991116'
TransformXPath2 = ''
TransformXPointer = ''
TransformXslt = 'http://www.w3.org/TR/1999/REC-xslt-19991116'
TransformRemoveXmlTagsC14N = ''
TransformVisa3DHack = ''
TransformAes128Cbc = ''
TransformAes192Cbc = ''
TransformAes256Cbc = ''
TransformKWAes128 = ''
TransformKWAes192 = ''
TransformKWAes256 = ''
TransformDes3Cbc = ''
TransformKWDes3 = ''
TransformDsaSha1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
TransformDsaSha256 = 'http://www.w3.org/2009/xmldsig11#dsa-sha256'
TransformEcdsaSha1 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1'
TransformEcdsaSha224 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224'
TransformEcdsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
TransformEcdsaSha384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'
TransformEcdsaSha512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512'
TransformHmacRipemd160 = 'http://www.w3.org/2001/04/' \
                         'xmldsig-more#hmac-ripemd160'
TransformHmacSha1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
TransformHmacSha224 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224'
TransformHmacSha256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'
TransformHmacSha384 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384'
TransformHmacSha512 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512'
TransformRsaMd5 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-md5'
TransformRsaRipemd160 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160'
TransformRsaSha1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
TransformRsaSha224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'
TransformRsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
TransformRsaSha384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
TransformRsaSha512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
TransformRsaPkcs1 = ''
TransformRsaOaep = ''
TransformMd5 = 'http://www.w3.org/2001/04/xmldsig-more#md5'
TransformRipemd160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160'
TransformSha1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
TransformSha224 = 'http://www.w3.org/2001/04/xmldsig-more#sha224'
TransformSha256 = 'http://www.w3.org/2001/04/xmlenc#sha256'
TransformSha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384'
TransformSha512 = 'http://www.w3.org/2001/04/xmlenc#sha512'

TransformUsageUnknown = {

}
TransformUsageDSigTransform = [
    TransformEnveloped
]
TransformUsageC14NMethod = {
    TransformInclC14N: {
        'method': 'c14n',
        'exclusive': False,
        'comments': False
    },
    TransformInclC14NWithComments: {
        'method': 'c14n',
        'exclusive': False,
        'comments': True
    },
    TransformExclC14N: {
        'method': 'c14n',
        'exclusive': True,
        'comments': False
    },
    TransformExclC14NWithComments: {
        'method': 'c14n',
        'exclusive': True,
        'comments': False
    }
}

TransformUsageDSigTransform.extend(TransformUsageC14NMethod.keys())

TransformUsageDigestMethod = {
    TransformMd5: 'md5',
    TransformSha1: 'sha1',
    TransformSha224: 'sha224',
    TransformSha256: 'sha256',
    TransformSha384: 'sha384',
    TransformSha512: 'sha512',
    TransformRipemd160: 'ripemd160',
}

TransformUsageSignatureMethod = {
    TransformRsaMd5: {
        'digest': hashes.MD5, 'method': RSAAlgorithm
    },
    TransformRsaSha1: {
        'digest': hashes.SHA1, 'method': RSAAlgorithm
    },
    TransformRsaSha224: {
        'digest': hashes.SHA224, 'method': RSAAlgorithm
    },
    TransformRsaSha256: {
        'digest': hashes.SHA256, 'method': RSAAlgorithm
    },
    TransformRsaSha384: {
        'digest': hashes.SHA384, 'method': RSAAlgorithm
    },
    TransformRsaSha512: {
        'digest': hashes.SHA512, 'method': RSAAlgorithm
    },
    TransformHmacSha1: {
        'digest': hashes.SHA1, 'method': HMACAlgorithm
    },
    TransformHmacSha224: {
        'digest': hashes.SHA256, 'method': HMACAlgorithm
    },
    TransformHmacSha256: {
        'digest': hashes.SHA256, 'method': HMACAlgorithm
    },
    TransformHmacSha384: {
        'digest': hashes.SHA384, 'method': HMACAlgorithm
    },
    TransformHmacSha512: {
        'digest': hashes.SHA512, 'method': HMACAlgorithm
    }
}

TransformUsageEncryptionMethod = {}
TransformUsageAny = {}
