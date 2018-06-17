import base64, bz2, datetime, os, re, sys
import logging
import json
import xml.etree.ElementTree as ET
from constants import DATA_HEADER_B64BZIP
from cresignedxml import creSignedXML
from wrapperrecord import *
from userexceptions import *
from xmlsigverifyer import XmlSigVerifyer
from xy509cert import XY509cert
__author__ = 'r2h2'


class AODSFileHandler():
    def __init__(self, cliClient):
        self._aodsFile = cliClient.args.aods
        self.verbose = cliClient.args.verbose
        self.list_trustedcerts = cliClient.args.list_trustedcerts

        if not cliClient.args.noxmlsign and self._aodsFile[-4:] != '.xml':
            self._aodsFile += '.xml'
        if cliClient.args.noxmlsign and self._aodsFile[-5:] != '.json':
            self._aodsFile += '.json'
        if not os.path.isfile(self._aodsFile) and \
                getattr(cliClient.args, 'subcommand', None) not in ('create', 'scratch'):
            errmsg = '--- Policy journal not found: ' + self._aodsFile + ' fix path or create'
            logging.error(errmsg)
            raise InvalidArgumentValueError(errmsg)
        if cliClient.args.trustedcerts is None:
            self.trustedCerts = []
        else:
            if not os.path.isfile(cliClient.args.trustedcerts):
                raise ValidationError('Trust certs file not found: %s' % self.trustCertsFile)
            with open(os.path.abspath(cliClient.args.trustedcerts)) as f:
                self.trustedCerts = json.loads(f.read())

    def _do_list_trustedcerts(self, signerCertificateEncoded):
        for cert in self.trustedCerts:
            #logging.debug('--- List of  certificates trusted to sign the policy journal. '
            #             'Certificate for current journal is marked with ">>".')
            #linemarker = ('>>' if cert == signerCertificateEncoded else '')
            xy509cert = XY509cert(cert, 'PEM')
            #logging.debug(linemarker + 's: ' + xy509cert.getSubject_str() +
            #             ', i:' + xy509cert.getIssuer_str() +
            #             'not after: ' + xy509cert.notValidAfter())
        #logging.debug('--- End of list of trusted certificates.')

    def create(self, s, noxmlsign):
        if os.path.exists(self._aodsFile):
            raise InvalidArgumentValueError('Must remove existing %s before creating a new AODS' %
                                            self._aodsFile)
        os.makedirs(os.path.dirname(self._aodsFile), exist_ok=True)
        if noxmlsign:
            with open(self._aodsFile, 'w') as f:
                f.write(json.dumps(s))
        else:
            j = json.dumps(s)
            x = creSignedXML(j, verbose=self.verbose)
            with open(self._aodsFile, 'w') as f:
                f.write(x)

    def readFile(self):
        if self._aodsFile[-4:] == '.xml':
            # verify whether the signature is valid
            xml_sig_verifyer = XmlSigVerifyer(testhint='aods signature');
            xml_sig_verifyer_response = xml_sig_verifyer.verify(self._aodsFile)
            # verify whether the signer is authorized
            if xml_sig_verifyer_response.signer_cert_pem not in self.trustedCerts:
                raise UnauthorizedAODSSignerError("Signature certificate of policy journal not in "
                    "trusted list. Certificate:\n" + xml_sig_verifyer_response.signer_cert_pem)
            if self.list_trustedcerts:
                self._do_list_trustedcerts(xml_sig_verifyer_response.signer_cert_pem)
            # get contents
            tree = ET.parse(self._aodsFile)
            content = tree.findtext('{http://www.w3.org/2000/09/xmldsig#}Object')
            if len(content) < 0:
                raise ValidationError('AODS contained in XML signature value is empty')
            # logging.debug('Found dsig:SignatureValue/text() in aods:\n%s\n' % content)
            content_body_str = content.replace(DATA_HEADER_B64BZIP, '', 1)
            j_bzip2 = base64.b64decode(content_body_str)
            j = bz2.decompress(j_bzip2)
            return json.loads(j.decode('UTF-8'))
        else:  # must be json
            with open(self._aodsFile, 'r') as f:
                j = json.loads(f.read())
            return j

    def removeFile(self):
        ''' remove file but ignore if it does not exist '''
        try:
            os.remove(self._aodsFile)
        except OSError as e:
            if e.errno != 2:
                raise e

    def save(self, s, noxmlsign):
        if noxmlsign:
            with open(self._aodsFile, 'w') as f:
                f.truncate()
                f.write(json.dumps(s))
        else:
            xml = creSignedXML(json.dumps(s))
            if len(xml) == 0:  # just for defense, should not happen
                raise EmptyAODSError('Journal empty, not saved - signature failed?')
            with open(self._aodsFile, 'w') as f:
                f.truncate()
                f.write(xml)

