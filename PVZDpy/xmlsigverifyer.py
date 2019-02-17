from pathlib import Path
from enforce import runtime_validation
from PVZDpy.xmlsigverifyer_moasp import XmlSigVerifyerMoasp
from PVZDpy.xmlsigverifyer_response import XmlSigVerifyerResponse
from PVZDpy.userexceptions import InvalidArgumentValueError


class XmlSigVerifyer():
    def __init__(self):
        self.xml_sig_verifier = XmlSigVerifyerMoasp()

    @runtime_validation
    def verify(self, xml_file_name: Path, verify_file_extension: bool = True) -> XmlSigVerifyerResponse:
        """ return signerCertificate """
        if verify_file_extension and xml_file_name.suffix != '.xml':
            raise InvalidArgumentValueError('XMl filename must have extension .xml')

        return self.xml_sig_verifier.verify(str(xml_file_name))
