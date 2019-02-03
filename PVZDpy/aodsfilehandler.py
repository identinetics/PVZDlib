import base64
import bz2
import datetime
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from PVZDpy.config.get_pvzdlib_config import get_pvzdlib_config
from PVZDpy.constants import DATA_HEADER_B64BZIP
from PVZDpy.cresignedxml_seclay_direct import cre_signedxml_seclay
from PVZDpy.trustedcerts import TrustedCerts
from PVZDpy.userexceptions import *
from PVZDpy.xmlsigverifyer import XmlSigVerifyer
from PVZDpy.xy509cert import XY509cert


class AodsFileHandler():
    def __init__(self):
        self.config = get_pvzdlib_config()
        self.backend = self.config.polstore_backend
        self.trusted_certs = TrustedCerts()

    def read(self):
        if self.config.xmlsign:
            pj_path = self.backend.get_policy_journal_path()
            xml_sig_verifyer = XmlSigVerifyer();
            xml_sig_verifyer_response = xml_sig_verifyer.verify(pj_path)
            logging.debug('XML signature is valid')

            if xml_sig_verifyer_response.signer_cert_pem not in self.trusted_certs.certs:
                raise UnauthorizedAODSSignerError("Signature certificate of policy journal not in "
                    "trusted list. Certificate:\n" + xml_sig_verifyer_response.signer_cert_pem)
            logging.debug('XML signature: signer is authorized')

            tree = ET.parse(pj_path)
            content = tree.findtext('{http://www.w3.org/2000/09/xmldsig#}Object')
            if len(content) < 0:
                raise ValidationError('AODS contained in XML signature value is empty')
            logging.debug('Found dsig:SignatureValue/text() in aods:\n%s\n' % content)
            content_body_str = content.replace(DATA_HEADER_B64BZIP, '', 1)
            j_bzip2 = base64.b64decode(content_body_str)
            j = bz2.decompress(j_bzip2)
            return json.loads(j.decode('UTF-8'))
        else:
            logging.warning('Loaded policy directory from unsigned JSON source - NO CRYPTOGRAPHIC TRUST')
            return json.loads(self.backend.get_poldir_json())

    def remove(self):
        self.config.polstore_backend.reset_pjournal_and_derived()

    def save(self, journal: dict, journal_html: str, shibacl: str):
        if self.config.xmlsign:
            j = json.dumps(journal)
            xml_str = cre_signedxml_seclay(j)
            self.backend.set_policy_journal(xml_str.encode('utf-8'))
        self.backend.set_poldir_json(j)
        self.backend.set_poldir_html(journal_html)
        self.backend.set_shibacl(shibacl)
