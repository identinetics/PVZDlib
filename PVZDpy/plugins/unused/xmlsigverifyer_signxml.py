import base64, bz2, datetime, logging, os, re, sys
import signxml
from constants import PROJDIR_ABS
import localconfig
from plugins.xmlsigverifyer_abstract import XmlSigVerifyerAbstract
from userexceptions import *
from xy509cert import XY509cert
__author__ = 'r2h2'


class XmlSigVerifyerSignxml(XmlSigVerifyerAbstract):
    """ verify xml signatures using python signxml """
    def __init__(self, sig_cert=None):
        self.sig_cert = sig_cert

    def verify(self, xml_file_name) -> str:
        """ verify xmldsig and return signerCertificate
        option: validate against a specific signing certificate.
        """
        with open(xml_file_name) as fd:
            xml_str = fd.read()
        xml_bytes = xml_str.encode(localconfig.XML_ENCODING)
        try:
            if self.sig_cert is None:  # TODO - does not work yet https://github.com/kislyuk/signxml/issues/41
                verified_et_element = signxml.xmldsig(xml_bytes).verify(
                        #ca_pem_file=localconfig.UNITTEST_CACERT,
                        ca_path=localconfig.UNITTEST_CADIR)
            else:
                with open(self.sig_cert) as fd:
                    cert = fd.read()
                verified_et_element = signxml.xmldsig(xml_bytes).verify(x509_cert=cert)
        except signxml.InvalidDigest:
            logging.info('Invalid digest in ' + xml_file_name)
            raise
        except signxml.InvalidInput:
            logging.info('Invalid input in ' + xml_file_name)
            raise

        signed_data_bytes = ElementTree.tostring(verified_et_element,
                                                 xml_declaration=True,
                                                 encoding=localconfig.XML_ENCODING)
        signed_data_str = signed_data_bytes.decode(localconfig.XML_ENCODING)
        cert_b64 = XY509cert.pem_remove_rfc7468_delimiters(cert,
                                                           optional_delimiter=True,
                                                           remove_whitespace=True)
        r = XmlSigVerifyerResponse(signed_data_str, cert_b64)
        return r
