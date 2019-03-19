import base64
import bz2
import logging
import requests
import re
# import socket
from PVZDpy.config.pvzdlib_config_abstract import PVZDlibConfigAbstract
from PVZDpy.constants import DATA_HEADER_B64BZIP
from PVZDpy.get_seclay_request import get_seclay_request
from PVZDpy.userexceptions import SecurityLayerCancelledError, ValidationError

def cre_signedxml_seclay(sig_data, sig_type='envelopingB64BZIP', sig_position=None):
    ''' Create XAdES signature using AT Bürgerkarte/Security Layer
        There are two signature types:
            1. envelopingB64BZIP: compress, b64-encode and sign the data (enveloping)
            2. enveloped: sign whole element specified py the XPath location
        Caveat: the XPAth for the position of the enveloping signature must use the
            QName prefix, not the namespace URI
            (e.g. md: instead of urn:oasis:names:tc:SAML:2.0:metadata:)
    '''

    if sig_type not in ('envelopingB64BZIP', 'enveloped'):
        raise ValidationError("Signature type must be one of 'envelopingB64BZIP', 'enveloped' but is " + sig_type)
    if sig_type == 'envelopingB64BZIP':
        dataObject = DATA_HEADER_B64BZIP + base64.b64encode(bz2.compress(sig_data.encode('utf-8'))).decode('ascii')
        xml_sig_type = 'enveloping'
    else:
        dataObject = re.sub(r'<\?xml.*>', '', sig_data)  # remove xml-header - provided by SecLay request wrapper
        xml_sig_type = 'enveloped'
    # logging.debug('data to be signed:\n%s\n\n' % dataObject)
    sigRequ = get_seclay_request(xml_sig_type, dataObject, sig_position)
    # logging.debug('SecLay request:\n%s\n' % sigRequ)
    try:
        s = requests.Session()
        req = requests.Request(
            'POST', 'http://localhost:3495/http-security-layer-request',
            data={'XMLRequest': sigRequ})
        prepped = req.prepare()
        logmsg = '{}\n{}\n{}\n\n{}'.format(
            '-----------HTTP Request Start -----------',
            prepped.method + ' ' + prepped.url,
            '\n'.join('{}: {}'.format(k, v) for k, v in prepped.headers.items()),
            prepped.body,
            '-----------HTTP Request End -----------'
        )
        logging.debug(logmsg)
        pvzdconf = PVZDlibConfigAbstract.get_config()
        testout_path = pvzdconf.testout / 'cresigrequ.xml'
        testout_path.write_text(logmsg)
        r = s.send(prepped)
    except requests.exceptions.ConnectionError as e:
        raise ValidationError("Cannot connect to security layer (MOCCA) to create a signature " + e.strerror)
    if r.status_code != 200:
        raise ValidationError("Security layer failed with HTTP %s, message: \n\n%s" % (r.status_code, r.text))
    if r.text.find('sl:ErrorResponse') >= 0:
        if r.text.find('<sl:ErrorCode>6001</sl:ErrorCode>'):
            # sys.tracebacklimit = 0  # bug in py3 - tracebacklimit not honored
            raise SecurityLayerCancelledError(
                'Signature cancelled by user. Securty Layer Code 6001. Other cause: trying to sign signed XML')
            # sl:ErrorCode=6001, Abbruch durch den Bürger über die Benutzerschnittstelle.
        else:
            raise ValidationError("Security Layer responed with error message.\n" + r.text)

    # Strip xml root element (CreateXMLSignatureResponse), making disg:Signature the new root:
    # (keeping namespace prefixes - otherwise the signature would break. Therefore not using etree.)
    logging.debug('security layer create signature response:\n%s\n' % r.text)
    testout_path = pvzdconf.testout / 'cresigresp.xml'
    testout_path.write_text(r.text)
    r1 = re.sub(r'<sl:CreateXMLSignatureResponse [^>]*>', '', r.text)
    r2 = re.sub(r'</sl:CreateXMLSignatureResponse>', '', r1)
    testout_path = pvzdconf.testout / 'signedxml.xml'
    testout_path.write_text(r2)
    return r2
