from datetime import datetime
import logging
import lxml.etree
import os
import re
from pathlib import Path
from OpenSSL import crypto
from urllib.parse import urlparse
from PVZDpy.constants import XMLNS_DSIG, XMLNS_MD, XMLNS_MD_PREFIX, XMLNS_MDRPI, XMLNS_MDRPI_PREFIX, XMLNS_PVZD_PREFIX
import PVZDpy.lxml_helper as lxml_helper
from PVZDpy.policydict import PolicyDict
from PVZDpy.samlentitydescriptor import SAMLEntityDescriptor
from PVZDpy.userexceptions import CertExpiredError, CertInvalidError, EdHostnameNotMatchingCertSubject
from PVZDpy.userexceptions import InputValueError, InvalidFQDNInEndpoint
from PVZDpy.userexceptions import InvalidFQDNinEntityID
from PVZDpy.xy509cert import XY509cert
from PVZDpy.xmlsigverifyer import XmlSigVerifyer
from PVZDpy.xmlsigverifyer_response import XmlSigVerifyerResponse
from PVZDpy.xy509certstore import Xy509certStore
from PVZDpy.xy509cert import XY509cert

__author__ = 'r2h2'


class SAMLEntityDescriptorPVP:
    """
    Instance of SAML EntityDescriptor with PVP profile specific extensions
    """
    def __init__(self, ed_path: str, policydict: PolicyDict):
        self.ed_path = ed_path
        self.ed = SAMLEntityDescriptor(ed_path)
        self.policydict = policydict
        issuers = self.policydict.get_issuers()
        self.IDP_trustStore = Xy509certStore(issuers, 'IDP')
        self.SP_trustStore = Xy509certStore(issuers, 'SP')

    def checkCerts(self) -> None:
        """ validate that included signing and encryption certificates meet following conditions:
            * not expired AND
            * issued by a CA listed as issuer in the related trust store) AND
            * the x509subject's CN matches the hostname of the entityDescriptor
        """
        for cert_pem in self._getCerts('IDP'):   # certs in IDPSSODescriptor elements
            if cert_pem is None:
                continue
            cert = XY509cert(cert_pem)
            if not cert.isNotExpired():
                raise CertExpiredError('Certificate is expired')
            x509storeContext = crypto.X509StoreContext(self.IDP_trustStore.x509store, cert.cert)
            try:
                x509storeContext.verify_certificate()
            except crypto.X509StoreContextError as e:
                raise CertInvalidError(('Certificate validation failed. ' + str(e) + ' ' + cert.getIssuer_str()))
            if cert.getSubject_str().find('/CN=' + self.get_entityid_hostname()) < 0:
                raise EdHostnameNotMatchingCertSubject(
                    'Hostname of entityID (%s) not matching CN in cert subject (%s)' %
                    (self.get_entityid_hostname(), cert.getSubject_str()))

        for cert_pem in self._getCerts('SP'):   # certs in SPSSODescriptor elements
            if cert_pem is None:
                continue
            cert = XY509cert(cert_pem)
            if not cert.isNotExpired():
                raise CertExpiredError(
                    f"Certificate is expired since {cert.notValidAfter()}; subject: {cert.getSubject_str}")
            x509storeContext = crypto.X509StoreContext(self.SP_trustStore.x509store, cert.cert)
            try:
                x509storeContext.verify_certificate()
            except crypto.X509StoreContextError as e:
                raise CertInvalidError(('Certificate validation failed. ' + str(e) + ' ' + cert.getIssuer_str()))
        logging.debug('Entity certificates valid for ' + self.ed.get_entityid())

    @staticmethod
    def create_delete(entityid: str) -> str:
        return """\
    <!-- DELETE entity descriptor from metadata -->
    <md:EntityDescriptor entityID="{eid}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:pvzd="http://egov.gv.at/pvzd1.xsd"
        pvzd:disposition="delete">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{eid}/idp/unused"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>""".format(eid=entityid)

    def _getCerts(self, role: str) -> list:
        certs = []
        if role == 'IDP':
            xp = 'md:IDPSSODescriptor//ds:X509Certificate'
        if role == 'SP':
            xp = 'md:SPSSODescriptor//ds:X509Certificate'
        i = 0
        for elem in self.ed.tree.xpath(xp, namespaces={'ds': XMLNS_DSIG, 'md': XMLNS_MD}):
            if elem.text:
                certs.append(elem.text)
            i += 1
        return certs

    def get_entityid(self) -> str:
        return self.ed.get_entityid()

    def get_filename_from_entityid(self) -> str:
        return SAMLEntityDescriptor.get_filename_from_entityid(self.ed.get_entityid)

    def get_entityid_hostname(self) -> str:
        entityID_url = self.ed.get_entityid()
        hostname = urlparse(entityID_url).hostname
        if hostname is None:
            return ''
        else:
            return hostname

    def get_namespace(self) -> str:
        fqdn = self.get_entityid_hostname()
        allowed_namespaces = self.policydict.get_registered_namespaces()
        namespace = PolicyDict.get_namesp_for_fqdn(fqdn, allowed_namespaces)
        return namespace

    def get_xml_str(self) -> None:
        return self.ed.get_xml_str()

    def isDeletionRequest(self) -> None:
        tree = lxml.etree.parse(self.ed_path)
        rootelem_attr = tree.getroot().attrib
        try:
            return rootelem_attr[XMLNS_PVZD_PREFIX + 'disposition'] == 'delete'
        except KeyError:
            return False

    @staticmethod
    def isInAllowedNamespaces(fqdn: str, allowed_namespaces: list) -> bool:
        """  check if fqdn is identical to or in a wildcard-namespace of an namespace allowed for signer """
        # TODO: change to explicit wildcards
        namespace = PolicyDict.get_namesp_for_fqdn(fqdn, allowed_namespaces)
        return (namespace is not None)

    def isInRegisteredNamespaces(self, fqdn: str) -> bool:
        """  check if fqdn is identical to or in a wildcard-namespace of a
             registered namespace (independet of signer) """
        # TODO: change to explicit wildcards
        registered_ns = self.policydict.get_registered_namespaces()
        namespace = PolicyDict.get_namesp_for_fqdn(fqdn, registered_ns)
        return (namespace is not None)

    def remove_enveloped_signature(self) -> None:
        lxml_helper.delete_element_if_existing(
            self.ed.tree,
            '/md:EntityDescriptor/ds:Signature',
            {'md': XMLNS_MD, 'ds': XMLNS_DSIG})

    @staticmethod
    def set_registrationinfo(tree, authority, fixed_date_for_unittest=False):
        lxml_helper.delete_element_if_existing(
            tree,
            '//md:EntityDescriptor/md:Extensions/mdrpi:RegistrationInfo',
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})
        new = lxml.etree.Element(XMLNS_MD_PREFIX + "Extensions")
        lxml_helper.insert_if_missing(
            tree,
            '//md:EntityDescriptor',
            '//md:EntityDescriptor/md:Extensions',
            new,
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})
        new = lxml.etree.Element(XMLNS_MDRPI_PREFIX + "RegistrationInfo")
        new.set(XMLNS_MDRPI_PREFIX + 'registrationAuthority', authority)
        if fixed_date_for_unittest:
            now = datetime(1900, 1, 1, 0, 0, 0, 0)
        else:
            now = datetime.now()
        now_iso8601 = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        new.set(XMLNS_MDRPI_PREFIX + 'registrationInstant', now_iso8601)
        lxml_helper.insert_if_missing(
            tree,
            '//md:EntityDescriptor/md:Extensions',
            '//md:EntityDescriptor/md:Extensions/mdrpi:RegistrationInfo',
            new,
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})

    def validateDomainNames(self, allowedDomains) -> bool:
        """ check that entityId and endpoints contain only hostnames from allowed namespaces"""
        if not SAMLEntityDescriptorPVP.isInAllowedNamespaces(self.get_entityid_hostname(), allowedDomains):
            raise InvalidFQDNinEntityID('FQDN of entityID %s not in namespaces allowed for signer: %s' %
                                        (self.get_entityid_hostname(), sorted(allowedDomains)))
        logging.debug('signer is allowed to use %s as entityID' % self.get_entityid_hostname())
        for attr_value in self.ed.tree.xpath('//md:*/@Location', namespaces={'md': XMLNS_MD}):
            location_hostname = urlparse(attr_value).hostname
            if not SAMLEntityDescriptorPVP.isInAllowedNamespaces(location_hostname, allowedDomains):
                raise InvalidFQDNInEndpoint('%s in %s not in allowed namespaces: %s' %
                                            (location_hostname, attr_value, sorted(allowedDomains)))
            logging.debug('signer is allowed to use %s in %s' % (location_hostname, attr_value))
        return True

    def validate_schematron(self) -> None:
        pass  # TODO: implement

    def validateSignature(self) -> XmlSigVerifyerResponse:
        xml_sig_verifyer = XmlSigVerifyer()
        xml_sig_verifyer_response = xml_sig_verifyer.verify(Path(self.ed_path))
        return xml_sig_verifyer_response

    def validate_xsd(self) -> None:
        return self.ed.validate_xsd()

    def verify_filename(self) -> None:
        """ verify if filename convention maps the entityID. Do _not_ call on object creation """
        basefn = os.path.basename(self.ed_path)
        # file name must have the format "*compressedEntityId.xml". Check right substring:
        fn = SAMLEntityDescriptor.get_filename_from_entityid(self.ed.get_entityid())
        if not re.search(str(fn) + '$', basefn):
            raise InputValueError('Invalid format for EntitiyDescriptor filename "%s". The file name '
                                  'for entityID %s must end with "%s" - see PAtool documentation.' %
                                  (basefn, self.get_entityid(), fn))

    def write(self, new_filename: str = None) -> None:
        fn = self.ed.ed_path if new_filename is None else new_filename
        self.ed.write(fn)
