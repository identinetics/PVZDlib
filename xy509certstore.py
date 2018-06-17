import logging, os
from OpenSSL import crypto
import xy509cert

__author__ = 'r2h2'

class Xy509certStore:
    def __init__(self, policyDict, pvprole):
        ''' transform isser-certs into trust stores '''
        self.x509store = crypto.X509Store()
        self.emtpy = True
        issuers = policyDict["issuer"]
        for subject in issuers:
            if pvprole == issuers[subject][0]:
                cert_pem = issuers[subject][1]
                logging.debug('Xy509certStore: cet_pem=' + cert_pem)
                caCert = xy509cert.XY509cert(cert_pem)
                self.x509store.add_cert(caCert.cert)
                self.emtpy = False
                #logging.debug('Adding CA cert for pvprole=' + pvprole + '; subject=' +
                #              caCert.getSubject_str() + '; cert:' + cert_pem)
