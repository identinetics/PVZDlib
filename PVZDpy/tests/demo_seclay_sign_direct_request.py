import html
import requests

# demo of how to redirect the browser to the security layer to request an enveloped signature



xml_to_be_signed = '''\
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
      
<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:pvzd="http://egov.gv.at/pvzd1.xsd" entityID="https://redmine.identinetics.com/idp.xml" pvzd:pvptype="R-Profile">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://redmine.identinetics.com/idp.xml/idp/unused"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>

      </sl:XMLContent>
    </sl:SignatureEnvironment>
    <sl:SignatureLocation xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Index="0">
      %s
    </sl:SignatureLocation>
  </sl:SignatureInfo>
</sl:CreateXMLSignatureRequest> ''' % ('/md:EntityDescriptor')

s = requests.Session()
req = requests.Request('POST', 'http://localhost:13495/http-security-layer-request',
                       data={'XMLRequest': xml_to_be_signed})
prepped_req = req.prepare()  # prep to have nice logging
logmsg = '{}\n{}\n{}\n\n{}'.format(
    '-----------HTTP Request Start -----------',
    prepped_req.method + ' ' + prepped_req.url,
    '\n'.join('{}: {}'.format(k, v) for k, v in prepped_req.headers.items()),
    prepped_req.body,
    '-----------HTTP Request End -----------')
# Merge environment settings into session
settings = s.merge_environment_settings(prepped_req.url, None, None, None, None)
resp = s.send(prepped_req, **settings)
print(resp.status_code)
print(resp.content)