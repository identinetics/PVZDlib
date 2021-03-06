import os
from pathlib import Path

DATA_HEADER_B64BZIP = '{signed data format: base64(bzip2)}\n'

PROJLIB = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# XML namespaces for lxml.etree
XMLNS_DSIG = 'http://www.w3.org/2000/09/xmldsig#'
XMLNS_DSIG_PREFIX = '{%s}' % XMLNS_DSIG
XMLNS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
XMLNS_MD_PREFIX = '{%s}' % XMLNS_MD
XMLNS_PVZD = 'http://egov.gv.at/pvzd1.xsd'
XMLNS_PVZD_PREFIX = '{%s}' % XMLNS_PVZD
XMLNS_MDRPI = 'urn:oasis:names:tc:SAML:2.0:metadata:rpi'
XMLNS_MDRPI_PREFIX = '{%s}' % XMLNS_MDRPI

SAML_MDPRI_REGISTRATIONAUTHORITY = 'http://www.test.portalverbund.gv.at'
# loglevles valid for this project
LOGLEVELS = {'CRITICAL': 50, 'ERROR': 40, 'WARNING': 30, 'INFO': 20, 'DEBUG': 10}
LOGLEVELS_BY_INT = dict((v, k) for k, v in LOGLEVELS.items())

# PolicyJounal content
RECORDTYPES = [
    "domain",
    "header",
    "issuer",
    "organization",
    "revocation",
    "userprivilege",
]
RECORDTYPES_MAXLEN = 0
for r in RECORDTYPES:
    if len(r) > RECORDTYPES_MAXLEN:
        RECORDTYPES_MAXLEN = len(r)

EXTRACT_SAMLED_XSLT= str(Path(__file__).parent / 'extract_ed.xslt')
TIDY_SAMLED_XSLT = str(Path(__file__).parent / 'tidy_samled.xslt')
