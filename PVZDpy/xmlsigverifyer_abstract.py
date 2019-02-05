class XmlSigVerifyerAbstract():
    def verify(self, xml_file_name) -> str:
        """ verify xmldsig and return signerCertificate """
        raise NotImplementedError
