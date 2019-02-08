import base64
import bz2
import json
import logging
import xml.etree.ElementTree as ET
from PVZDpy.config.appconfig_abstract import PVZDlibConfigAbstract
from PVZDpy.constants import DATA_HEADER_B64BZIP
from PVZDpy.cresignedxml_seclay_direct import cre_signedxml_seclay
from PVZDpy.trustedcerts import TrustedCerts
from PVZDpy.userexceptions import PolicyJournalNotInitialized, UnauthorizedAODSSignerError, ValidationError
from PVZDpy.xmlsigverifyer import XmlSigVerifyer


class AodsFileHandler():
    def __init__(self):
        self.pvzdconf = PVZDlibConfigAbstract.get_config()
        self.backend = self.pvzdconf.polstore_backend
        self.trusted_certs = TrustedCerts().certs

    def read(self):
        if self.pvzdconf.xmlsign:
            pj_path = self.backend.get_policy_journal_path()
            if not pj_path.is_file():
                raise PolicyJournalNotInitialized
            xml_sig_verifyer = XmlSigVerifyer()
            xml_sig_verifyer_response = xml_sig_verifyer.verify(pj_path)
            logging.debug('XML signature is valid')

            if xml_sig_verifyer_response.signer_cert_pem not in self.trusted_certs:
                raise UnauthorizedAODSSignerError(
                    "Signature certificate of policy journal not in "
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
            aods = json.loads(j.decode('UTF-8'))
        else:
            logging.warning('Loaded policy directory from unsigned JSON source - NO CRYPTOGRAPHIC TRUST')
            aods_json = self.backend.get_policy_journal_json()
            aods = json.loads(aods_json)
        return aods

    def remove(self):
        self.pvzdconf.polstore_backend.reset_pjournal_and_derived()

    def save_journal(self, journal: dict):
        journal_json = json.dumps(journal)
        if self.pvzdconf.xmlsign:
            xml_str = cre_signedxml_seclay(journal_json)
        else:
            xml_str = ''
        self.backend.set_policy_journal_xml(xml_str.encode('utf-8'))
        self.backend.set_policy_journal_json(journal_json)

    def save_policydict_json(self, dict_json: str):
        self.backend.set_poldict_json(dict_json)

    def save_policydict_html(self, dict_html: str):
        self.backend.set_poldict_html(dict_html)

    def save_shibacl(self, shibacl: str):
        self.backend.set_shibacl(shibacl)

    def save_trustedcerts_report(self, cert_report: str):
        self.backend.set_trustedcerts_report(cert_report)
