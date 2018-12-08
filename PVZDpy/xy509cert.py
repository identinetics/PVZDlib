import re
import textwrap
from datetime import datetime
from OpenSSL import crypto
from .userexceptions import *
__author__ = 'r2h2'


class XY509cert:
    ''' Wrapper for OpenSSL.crypto.x509 to add a few methods. (yes, could have
        been done with a subclass as well)
    '''
    def __init__(self, cert_str, inform='PEM'):
        if inform == 'PEM':
            c =  XY509cert.pem_add_rfc7468_delimiters(cert_str)
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, c)
        elif inform == 'DER':
            self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_str)
        self.cert_str = cert_str

    @staticmethod
    def pem_add_rfc7468_delimiters(cert_str: str) -> str:
        """ take a base64-encoded certificate and add BEGIN/END lines if they are missing;
            wrap lines > 76 characters, because older versions of openssl (< 1.0.2?) limit base64
            lines like MIME
        """
        cert_str_normalized = cert_str.replace('\r\n','\n')
        hasStartLine = False
        new_cert = ''
        for l in cert_str_normalized.splitlines(True):
            if l.lstrip() == '-----BEGIN CERTIFICATE-----\n':
                hasStartLine = True
            elif hasStartLine:
                l = '\n'.join(textwrap.wrap(l, 64)) + '\n'
                #print("line: " + l)
            new_cert += l
        if not hasStartLine:
            c = '-----BEGIN CERTIFICATE-----\n' + \
                '\n'.join(textwrap.wrap(cert_str, 64)) + \
                '\n-----END CERTIFICATE-----\n'
        else:
            c = new_cert
            #print("Zertifikat: " + c)
        return re.sub(r'\n\s*\n', '\n', c)  # openssl dislikes blank lines before the end line

    @staticmethod
    def pem_remove_rfc7468_delimiters(cert_str,
                                      optional_delimiter=False,
                                      remove_whitespace=False) -> str:
        """ take a base64-encoded certificate and remove BEGIN/END lines
            raise ValidationError if either is missing, unless optional_delimiter is True
        """
        begin = False
        end = False
        pem_str = ''
        for l in cert_str.splitlines(True):
            if l == '-----BEGIN CERTIFICATE-----\n':
                begin = True
                continue
            if begin:
                if l.startswith('-----END CERTIFICATE-----'):
                    end = True
                    break
                pem_str += l
        if optional_delimiter:
            pass
        else:
            if not begin:
                raise ValidationError("PEM file must have '-----BEGIN CERTIFICATE-----' header conforming to RFC 7468")
            if not end:
                raise ValidationError("PEM file must have '-----END CERTIFICATE-----' header conforming to RFC 7468")
        if remove_whitespace:
            return re.sub(r'\s', '', pem_str)
        else:
            return pem_str

    def getPEM_str(self) -> str:
        return XY509cert.pem_remove_rfc7468_delimiters(self.cert_str)

    def getSubjectCN(self) -> str:
        subject_dn = self.cert.get_subject()
        for (k, v) in subject_dn.get_components():
            if k.decode('utf-8') == 'CN':
                return v.decode('utf-8')

    def getSubject_str(self) -> str:
        subject_dn = self.cert.get_subject()
        subject_str = str(subject_dn).replace("<X509Name object '", '')[:-2]
        return subject_str

    def getIssuer_str(self) -> str:
        issuer_dn = self.cert.get_issuer()
        issuer_str = str(issuer_dn).replace("<X509Name object '", '')[:-2]
        return issuer_str

    def notValidAfter(self, formatted=False) -> str:
        raw = self.cert.get_notAfter().decode('ascii')
        if formatted:
            datestr = '%s-%s-%s %s:%s:%s' % (raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:12], raw[12:])
        else:
            datestr = raw
        return datestr

    def notAfter_str(self) -> str:
        return self.cert.get_notAfter().decode('ascii')

    def isNotExpired(self) -> bool:
        notValidAfter_str = self.cert.get_notAfter().decode('ascii')
        notValidAfter_date = datetime.strptime(notValidAfter_str, '%Y%m%d%H%M%SZ')
        return notValidAfter_date > datetime.now()

    def get_serial_number_int(self) -> int:
        return self.cert.get_serial_number()

    def get_serial_number_hex(self) -> int:
        x = format(self.cert.get_serial_number(), 'x')
        return ':'.join(x[i:i+2] for i in range(0, len(x), 2))

    def get_pubkey(self) -> str:
        return self.cert.get_pubkey().decode('ascii')


    def digest(self, dgst='SHA1') -> str:
        return self.cert.digest(dgst).decode('ascii')
