from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
#import urllib

def main(xml_to_be_signed):
    server_address = ('127.0.0.1', 13080)
    print(f'starting server at {server_address[0]}:{server_address[1]}')
    httpd = HTTPServer(server_address, RequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"GET request,\nPath: {str(self.path)}\nHeaders:\n{str(self.headers)}")
        self._set_response()
        create_xml_signature_request = self._get_CreateXMLSignatureRequest(xml_to_be_signed)
        post_data = create_xml_signature_request
        seclay_post_request_form = self._get_seclay_post_request_form().format(post_data)
        self.wfile.write(seclay_post_request_form.encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info(f"POST request,\nPath: str(self.path)\nHeaders:\n{str(self.headers)}\n\nBody:\n{post_data.decode('utf-8')}\n")

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _get_sig_data_req_template(self):
        return '''
<html>
  <body">
    <form method="POST" action="createsignature">
      <input type="hidden" name="EntityDescriptor" value="<%= request.getAttribute("EntityDescriptor") %>">
    </form>
    <textarea rows="500" cols="120">
{}
    </textarea>
  </body>
</html>
            '''

    def _get_seclay_post_request_form(self):
        return '''\
<!DOCTYPE html>
<html>
  <head><meta charset="utf-8" /></head>
  <body> <!--onload="document.forms[0].submit()"-->
    <p>you must press the Continue button once to proceed.</p>
    <form action="http://localhost:13495/http-security-layer-request" method="post">
      <input type="hidden" name=" "/>
            <textarea rows="20" cols="100" name="XMLRequest">{}</textarea>
      <input type="submit" value="Continue"/>
    </form>
  </body>
</html>
            '''

    def _get_CreateXMLSignatureRequest(self, res_content):
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
        {}
      </sl:XMLContent>
    </sl:SignatureEnvironment>
    <sl:SignatureLocation xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Index="0">
      {}
    </sl:SignatureLocation>
  </sl:SignatureInfo>
</sl:CreateXMLSignatureRequest>
        '''.format(res_content, '/md:EntityDescriptor')


def run(server_class=HTTPServer, handler_class=RequestHandler, port=14080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    xml_to_be_signed = '''\
<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:pvzd="http://egov.gv.at/pvzd1.xsd" entityID="https://redmine.identinetics.com/idp.xml" pvzd:pvptype="R-Profile">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://redmine.identinetics.com/idp.xml/idp/unused"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
            '''
    main(xml_to_be_signed)