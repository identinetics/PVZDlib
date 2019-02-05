import BaseHTTPRequestHandler
import logging
import urllib


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        with open('testdata/xmlsig_response.xml') as fd:
            self.expected_signed_data = fd.read()
        with open('testdata/unsigned_data.xml') as fd:
            self.xml_to_be_signed = fd.read()
        self.sig_response = ''
        super().__init__(*args, **kwargs)

    def _set_response(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        logging.info(f"GET request,\nPath: {str(self.path)}\nHeaders:\n{str(self.headers)}")
        if self.path == '/favicon.ico':
            self.send_response(404)
        elif self.path == '/automate.js':
            with open('automate.js') as fd:
                self.send_response(200)
                self.send_header('Content-type', 'application/javascript')
                self.end_headers()
                self.wfile.write(fd.read().encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            create_xml_signature_request = self._get_CreateXMLSignatureRequest(self.xml_to_be_signed)
            post_data = create_xml_signature_request
            seclay_post_request_form = self._get_seclay_post_request_form() % (post_data)
            self.wfile.write(seclay_post_request_form.encode('utf-8'))
            print("Signing request page sent")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self.sig_response = urllib.parse.unquote(post_data.decode('utf-8'))
        logging.info(f"POST request with signed data, form data:\n{self.sig_response}\n")
        if self.expected_signed_data != self.sig_response:
            logging.error("Signed data not matching expected result")
        else:
            print("signed data received")

        self._set_response()
        result_page = self._get_result_page(self.sig_response)
        self.wfile.write(result_page.encode('utf-8'))

    def _get_seclay_post_request_form(self):
        return '''\
<!DOCTYPE html>
<html>
  <head><meta charset="utf-8" /></head>
  <body> <!--onload="document.forms[0].submit()"-->
    <p>Request page - this page should not be shown in the browser unless java script is disabled</p>
    <textarea rows="30" cols="100" readonly name="XMLRequest">%s</textarea>
    <form action="http://localhost:8080/" method="post">
      <input type="hidden" name="signed_data"/>
      <input type="submit" value="Continue"/>
    </form>
    <script src="automate.js"></script>
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

    def _get_result_page(self, sig_response):
        return '''\
        <!DOCTYPE html>
        <html>
          <head><meta charset="utf-8" /></head>
          <body>
            <p>Result page (you must reload the page to trigger the javascript function requesting the signature)</p>
            <p>Signature Service Response:</p>
            <textarea rows="30" cols="100" readonly>
              %s
            </textarea>
          </body>
        </html>
            ''' % sig_response
