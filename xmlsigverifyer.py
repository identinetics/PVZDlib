import localconfig
if localconfig.xmldsiglib == localconfig.XMLDSIGLIB_SECLAY:
    from plugins.xmlsigverifyer_moasp import *
elif localconfig.xmldsiglib == localconfig.XMLDSIGLIB_SIGNXML:
    from plugins.xmlsigverifyer_signxml import XmlSigVerifyerSignxml

__author__ = 'r2h2'


class XmlSigVerifyer():
    def __init__(self, testhint=None):
        if localconfig.xmldsiglib == localconfig.XMLDSIGLIB_SECLAY:
            self.xml_sig_verifier = XmlSigVerifyerMoasp()
        #elif localconfig.xmldsiglib == localconfig.XMLDSIGLIB_SIGNXML:
        #    """ The test hint is is required because signxml does not validate against
        #    a CA or multiple certificates (issue reported).
        #    """
        #    if testhint is None:
        #        self.xml_sig_verifier = XmlSigVerifyerSignxml()
        #    elif testhint == 'PEPrequest':
        #        self.xml_sig_verifier = XmlSigVerifyerSignxml(sig_cert=localconfig.AUTHZSIGCERT)
        #    elif testhint == 'aods signature':
        #        self.xml_sig_verifier = XmlSigVerifyerSignxml(sig_cert=localconfig.AODSSIGCERT)
        else:
            raise NotImplementedError
        self.testhint=testhint

    def verify(self, xml_file_name, verify_file_extension=True) -> str:
        """ verify xmldsig and return signerCertificate """
        if verify_file_extension and xml_file_name[-4:] != '.xml':
            raise InvalidArgumentValueError('XMl filename must have extension .xml')

        return self.xml_sig_verifier.verify(xml_file_name)
