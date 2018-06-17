import base64, lxml.etree, signxml
md_dom = lxml.etree.parse('metadata.xml')
md_root = md_dom.getroot()
with open('metadata_crt.pem', 'r') as fd:
    md_cert_pem = fd.read()
asserted_metadata = signxml.xmldsig(md_root).verify(x509_cert=md_cert_pem)
