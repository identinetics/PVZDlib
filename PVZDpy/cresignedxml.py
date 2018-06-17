import base64, bz2, sys
import logging
import requests
import re
from .cresignedxml_seclay import *

__author__ = 'r2h2'


def creSignedXML(sig_data, sig_type='envelopingB64BZIP', sig_position=None, verbose=False):
    ''' Create XML signature '''

    return cre_signedxml_seclay(sig_data,
                                sig_type=sig_type,
                                sig_position=sig_position,
                                verbose=verbose)


if __name__ == '__main__':
    """ main for simplified command-line tests of XML documents with a dummy md:EntityDescriptor as root element """
    print("args=" + sys.argv[1] + "\n")
    if sys.argv[1] == 'Enveloping':
        print("Enveloping signature\n")
        print(creSignedXML('Test string', verbose=True))
    elif sys.argv[1] == 'Enveloped':
        print("Enveloped signature\n")
        ed = '''\
<md:EntityDescriptor entityID="https://gondor.magwien.gv.at/idp"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>MIIFxjCCBK6gAwIBAgICAlswDQYJKoZIhvcNAQELBQAwgZgxCzAJBgNVBAYTAkFUMQ0wCwYDVQQIEwRXaWVuMScwJQYDVQQKEx5CdW5kZXNtaW5pc3Rlcml1bSBmdWVyIElubmVyZXMxDjAMBgNVBAsTBUlULU1TMRkwFwYDVQQDExBQb3J0YWx2ZXJidW5kLUNBMSYwJAYJKoZIhvcNAQkBFhdibWktaXYtMi1lLWNhQGJtaS5ndi5hdDAeFw0xNTA3MTUwNzU2MTNaFw0xNzA4MDMwNzU2MTNaMIGEMQswCQYDVQQGEwJBVDEhMB8GA1UEChMYTWFnaXN0cmF0IGRlciBTdGFkdCBXaWVuMQ4wDAYDVQQLEwVNQSAxNDEdMBsGA1UEAxMUZ29uZG9yLm1hZ3dpZW4uZ3YuYXQxIzAhBgkqhkiG9w0BCQEWFHBvc3RAbWExNC53aWVuLmd2LmF0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2wvSx495pwJlN6ILaz+/0TQKARv7U0vJLggmQBheYhka5nEt6Oq9d2Zd6/QlTLSVcNp0GCZ3f1kMj842MatnGqAPdmtnSEQTLsOb6hKOC1ZE1g2yKJYxM7iyjsb+ZVCnfDZegn+P5n06Gzzh8UlQvD5h/lGVE//PZAu35oY2IpSAkvFEke8sT9ZdqFGWdcLFnzpt8JHbvfHLgWC63N/7UbVuLBQ/no0ynJBlUB+RGm1G+HkZl1SxNg9ul4Sakil/IiXadA+Cc9XEaV/W0dV2HEzkS8mtSY75bjMs0jiepwxAzKwi09Sfo8xrs8VyG6hkwF63+PyqtL5V3MS2LOR/awIDAQABo4ICKjCCAiYwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBQwexiDS7rYLmA4t03y7Gj1xoV6MTCB0QYDVR0jBIHJMIHGgBSmHvReGkO0iN6iyL1oZQPFMG9m06GBqqSBpzCBpDELMAkGA1UEBhMCQVQxDTALBgNVBAgTBFdpZW4xDTALBgNVBAcTBFdpZW4xJzAlBgNVBAoTHkJ1bmRlc21pbmlzdGVyaXVtIGZ1ZXIgSW5uZXJlczEOMAwGA1UECxMFSVQtTVMxFjAUBgNVBAMTDVBvcnRhbFJvb3QtQ0ExJjAkBgkqhkiG9w0BCQEWF2JtaS1pdi0yLWUtY2FAYm1pLmd2LmF0ggEBMB8GA1UdEQQYMBaBFHBvc3RAbWExNC53aWVuLmd2LmF0MCIGA1UdEgQbMBmBF2JtaS1pdi0yLWUtY2FAYm1pLmd2LmF0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9wb3J0YWwuYm1pLmd2LmF0L3JlZi9wa2kvcG9ydGFsQ0EvUG9ydGFsVi5jcmwwTwYIKwYBBQUHAQEEQzBBMD8GCCsGAQUFBzAChjNodHRwOi8vcG9ydGFsLmJtaS5ndi5hdC9yZWYvcGtpL3BvcnRhbENBL2luZGV4Lmh0bWwwDgYHKigACgEBAQQDAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQACkWwa0E3XcQRO0Z77wCqQpWyalFv6TH9OD9GQkXsg5P24Uqrm6Cpfq0wd612EfC5y4hqTz2nOqNHo6lcvoMOQimjimZTp4tLcMgqTt5NxniEKsRhH/4OKMrtaK7/erwn/8PyK7zT+NwTXo2UhTLW1eO8E2irItZ1jyN8fuj1J3OfoEJ3H+NSxWuSxr7pbNy7HvnPtGqPOlpgw4nhRQM5OP0CJxSbwO1hpBM5vd+yEauXZrCxv7AZCL7SqkRvIV2D4wnr9ddAsH2eGwXfKVgXKD46Z+S8L9CL/EUQdlEULqI5PlQ9qJWKp5P5UMvBd0SM0Tvd6WnJYA11vS6LM0bHG</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://gondor.magwien.gv.at/R-Profil-dummy"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>'''

        print(creSignedXML(ed, 'enveloped', sig_position='/md:EntityDescriptor', verbose=True))
    else:
        print('invalid argument')