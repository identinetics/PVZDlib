from .xmlsigverifyer_moasp import *

__author__ = 'r2h2'


class XmlSigVerifyer():
    def __init__(self):
        self.xml_sig_verifier = XmlSigVerifyerMoasp()

    def verify(self, xml_file_name, verify_file_extension=True) -> str:
        """ verify xmldsig and return signerCertificate """
        if verify_file_extension and xml_file_name[-4:] != '.xml':
            raise InvalidArgumentValueError('XMl filename must have extension .xml')

        return self.xml_sig_verifier.verify(xml_file_name)
