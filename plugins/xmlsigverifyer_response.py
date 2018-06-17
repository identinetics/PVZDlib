__author__ = 'r2h2'

class XmlSigVerifyerResponse():

    def __init__(self, sigdata, signer_cert_pem):
        self.sigdata = sigdata
        self.signer_cert_pem = signer_cert_pem
