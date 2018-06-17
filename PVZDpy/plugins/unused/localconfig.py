import logging
import os

XMLDSIGLIB_SECLAY='AT_CC_Security_Layer'
XMLDSIGLIB_SIGNXML='py_signxml'
# set default library for XMLDSIG:
xmldsiglib = XMLDSIGLIB_SECLAY
XML_ENCODING = 'utf-8'

try:
    # SIGNXML is not used currently, only for testing as alternative to MOA-SS/Citizen Card
    if os.environ['XMLDSIGLIB'] == XMLDSIGLIB_SIGNXML:
        xmldsiglib = XMLDSIGLIB_SIGNXML
        # set default signing certs
        unittest_certdir = '../tests/testdata/signxml_ca'
        UNITTEST_CADIR = os.path.join(unittest_certdir, 'cadir')
        #UNITTEST_CACERT = os.path.join(UNITTEST_CADIR, 'unittest_ca-cer.pem')
        AODSSIGCERT = os.path.join(unittest_certdir, 'aods_signer-cer.pem')
        AODSSIGKEY = os.path.join(unittest_certdir, 'aods_signer-key.pem')
        AUTHZSIGCERT = os.path.join(unittest_certdir, 'authz_signer-cer.pem')
        AUTHZSIGKEY = os.path.join(unittest_certdir, 'authz_signer-key.pem')
        XML_ENCODING = 'utf-8'
        logging.debug('using signxml library for xml signature')
    elif os.environ['XMLDSIGLIB'] == XMLDSIGLIB_SECLAY:
        pass
    else:
        raise NotImplementedError(os.environ['XMLDSIGLIB'] +
                                  ' is not an implemented value for XMLDSIGLIB')
except KeyError:
    pass

# part of filename to avoid confusion:
AODS_INDICATOR = ('signxml' if xmldsiglib == XMLDSIGLIB_SIGNXML else 'MOA')
