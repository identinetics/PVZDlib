from pathlib import Path
from PVZDpy.xmlsigverifyer_moasp import *


class XmlSigVerifyer():
    def __init__(self):
        self.xml_sig_verifier = XmlSigVerifyerMoasp()

    def verify(self, xml_file_name: Path, verify_file_extension=True) -> str:
        """ return signerCertificate """
        if verify_file_extension and xml_file_name.suffix != '.xml':
            raise InvalidArgumentValueError('XMl filename must have extension .xml')

        return self.xml_sig_verifier.verify(str(xml_file_name))
