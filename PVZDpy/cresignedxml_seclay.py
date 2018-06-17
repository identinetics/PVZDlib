import base64, bz2, sys
import logging
import requests
import re
import socket
from .constants import DATA_HEADER_B64BZIP
from .userexceptions import *

__author__ = 'r2h2'

def fail_if_securitylayer_unavailable():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = ('127.0.0.1', 3495)
    if sock.connect_ex(addr) != 0:
        #sys.tracebacklimit = 0
        raise SecurityLayerUnavailableError(SecurityLayerUnavailableError.__doc__)
    sock.close()

def get_seclay_requesttemplate(sigType, sigPosition=None) -> str:
    ''' return an XML template to be merged with the data to be signed
        sigPosition is the XPath for the element under which an enveoped signature shall
        be positioned, e.g. <md:/EntitiyDescriptor>
    '''
    if sigType == 'envelopingB64BZIP':
        return '''\
<?xml version="1.0" encoding="UTF-8"?>
<sl:CreateXMLSignatureRequest
  xmlns:sl="http://www.buergerkarte.at/namespaces/securitylayer/1.2#">
  <sl:KeyboxIdentifier>SecureSignatureKeypair</sl:KeyboxIdentifier>
  <sl:DataObjectInfo Structure="enveloping">
    <sl:DataObject>
      <sl:XMLContent>%s</sl:XMLContent>
    </sl:DataObject>
    <sl:TransformsInfo>
      <sl:FinalDataMetaInfo>
        <sl:MimeType>text/plain</sl:MimeType>
      </sl:FinalDataMetaInfo>
    </sl:TransformsInfo>
  </sl:DataObjectInfo>
</sl:CreateXMLSignatureRequest> '''
    if sigType == 'enveloped':
        return '''\
<?xml version="1.0" encoding="UTF-8"?>
<sl:CreateXMLSignatureRequest
  xmlns:sl="http://www.buergerkarte.at/namespaces/securitylayer/1.2#">
  <sl:KeyboxIdentifier>SecureSignatureKeypair</sl:KeyboxIdentifier>
  <sl:DataObjectInfo Structure="detached">
    <sl:DataObject Reference=""></sl:DataObject>
    <sl:TransformsInfo>
	<dsig:Transforms xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      </dsig:Transforms>
      <sl:FinalDataMetaInfo>
        <sl:MimeType>application/xml</sl:MimeType>
      </sl:FinalDataMetaInfo>
    </sl:TransformsInfo>
  </sl:DataObjectInfo>
  <sl:SignatureInfo>
    <sl:SignatureEnvironment>
      <sl:XMLContent>
%s
      </sl:XMLContent>
    </sl:SignatureEnvironment>
    <sl:SignatureLocation xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Index="0">%s</sl:SignatureLocation>
  </sl:SignatureInfo>
</sl:CreateXMLSignatureRequest> ''' % ('%s', sigPosition)

def cre_signedxml_seclay(sig_data, sig_type='envelopingB64BZIP', sig_position=None, verbose=False):
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
    fail_if_securitylayer_unavailable()
    if sig_type == 'envelopingB64BZIP':
        dataObject = DATA_HEADER_B64BZIP + base64.b64encode(bz2.compress(sig_data.encode('utf-8'))).decode('ascii')
    else:
        dataObject = re.sub('<\?xml.*>', '', sig_data)  #remove xml-header - provided by SecLay request wrapper
    logging.debug('data to be signed:\n%s\n\n' % dataObject)
    sigRequ = get_seclay_requesttemplate(sig_type, sig_position) % dataObject
    logging.debug('SecLay request:\n%s\n' % sigRequ)
    try:
        s = requests.Session()
        req = requests.Request('POST', 'http://localhost:3495/http-security-layer-request',
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
        #if verbose:
        #    print(logmsg)
        r = s.send(prepped)
    except requests.exceptions.ConnectionError as e:
        raise ValidationError("Cannot connect to security layer (MOCCA) to create a signature " + e.strerror)
    if r.status_code != 200:
        raise ValidationError("Security layer failed with HTTP %s, message: \n\n%s" % (r.status_code, r.text))
    if r.text.find('sl:ErrorResponse') >= 0:
        if r.text.find('<sl:ErrorCode>6001</sl:ErrorCode>'):
            #sys.tracebacklimit = 0  # bug in py3 - tracebacklimit not honored
            raise SecurityLayerCancelledError('Signature cancelled by user. Securty Layer Code 6001. Other cause: trying to sign signed XML')
            # sl:ErrorCode=6001, Abbruch durch den Bürger über die Benutzerschnittstelle.
        else:
            raise ValidationError("Security Layer responed with error message.\n" + r.text)

    # Strip xml root element (CreateXMLSignatureResponse), making disg:Signature the new root:
    # (keeping namespace prefixes - otherwise the signature would break. Therefore not using etree.)
    logging.debug('security layer create signature response:\n%s\n' % r.text)
    r1 = re.sub(r'<sl:CreateXMLSignatureResponse [^>]*>', '', r.text)
    r2 = re.sub(r'</sl:CreateXMLSignatureResponse>', '', r1)
    return r2
