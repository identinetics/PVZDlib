__author__ = 'r2h2'

class XmlSigVerifyerAbstract():
    def verify(self, xml_file_name, testhint=None) -> str:
        """ verify xmldsig and return signerCertificate """
        raise NotImplementedError