import base64, bz2, sys
import logging
#from xml.etree import ElementTree
from lxml import etree as ElementTree
from signxml import *
from constants import DATA_HEADER_B64BZIP
import localconfig

__author__ = 'r2h2'

def cre_signedxml_signxml(sig_data, sig_type='envelopingB64BZIP',
                          sig_position=None, verbose=False,
                          sig_cert=None, sig_key=None):
    ''' Create XML signature using py signxml (based on lxml + openssl) '''
    sig_cert = (localconfig.AODSSIGCERT if sig_cert is None else sig_cert)
    sig_key = (localconfig.AODSSIGKEY if sig_key is None else sig_key)
    with open(sig_cert) as fd:
        cert = fd.read()
    with open(sig_key) as fd:
        key = fd.read().encode('ascii')

    if sig_type == 'envelopingB64BZIP':
        dataObject = DATA_HEADER_B64BZIP + \
                     base64.b64encode(bz2.compress(sig_data.encode('utf-8'))).decode('ascii')
        logging.debug('data to be signed:\n%s\n\n' % dataObject)
        signed_root = xmldsig(dataObject).sign(method=methods.enveloping, key=key, cert=cert)
    elif sig_type == 'enveloped':
        root = ElementTree.fromstring(sig_data)
        if root.tag == '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor':
            # add <ds:Signature Id="placeholder"></ds:Signature> for signxml, ignoring sig_position
            # see also: https://signxml.readthedocs.org/en/latest/index.html
            DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#'
            NS_MAP = {'ds': DSIG_NS}
            ds_placeholder_name = ElementTree.QName(DSIG_NS, 'Signature')
            ds_placeholder = ElementTree.Element(ds_placeholder_name, nsmap=NS_MAP)
            ds_placeholder.attrib['Id']='placeholder'
            root.insert(0, ds_placeholder)
        signed_root = xmldsig(root).sign(method=methods.enveloped,
                                         key=key, cert=cert)
    else:
        raise ValidationError("Signature type must be one of 'envelopingB64BZIP', 'enveloped' but is " + sig_type)

    xml_bytes = ElementTree.tostring(signed_root, xml_declaration=True, encoding=localconfig.XML_ENCODING)
    xml_str = xml_bytes.decode(localconfig.XML_ENCODING)
    # verify what has bees signed:
    # verified_et_element = xmldsig(xml_str.encode(xml_encoding)).verify(x509_cert=cert)
    return xml_str