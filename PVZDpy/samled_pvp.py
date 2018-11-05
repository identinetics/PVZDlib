from datetime import datetime
import logging
import lxml.etree
import os
import re
import sys
from OpenSSL import crypto
from urllib.parse import urlparse
from .constants import *
from .samlentitydescriptor import SAMLEntityDescriptor
from .userexceptions import *
from .xy509cert import XY509cert
from .xmlsigverifyer import XmlSigVerifyer
from .xy509certstore import Xy509certStore
from .xy509cert import XY509cert

__author__ = 'r2h2'


class SAMLEntityDescriptorPVP:
    """
    Instance of SAML EntityDescriptor with PVP profile specific extensions
    """
    def __init__(self, ed_path, policyDict):
        self.ed_path = ed_path
        self.ed = SAMLEntityDescriptor(ed_path)
        self.policyDict = policyDict
        self.IDP_trustStore = Xy509certStore(policyDict, 'IDP')
        self.SP_trustStore = Xy509certStore(policyDict, 'SP')

    def checkCerts(self):
        """ validate that included signing and encryption certificates meet following conditions:
            * not expired AND
            * issued by a CA listed as issuer in the related trust store) AND
            * the x509subject's CN matches the hostname of the entityDescriptor
        """
        for cert_pem in self._getCerts('IDP'):   # certs in IDPSSODescriptor elements
            cert = XY509cert(cert_pem)
            if not cert.isNotExpired():
                raise CertExpiredError('Certificate is expired')
            x509storeContext = crypto.X509StoreContext(self.IDP_trustStore.x509store, cert.cert)
            try:
                x509storeContext.verify_certificate()
            except crypto.X509StoreContextError as e:
                raise CertInvalidError(('Certificate validation failed. ' + str(e) + ' ' +
                                        cert.getIssuer_str()))
            if cert.getSubject_str().find('/CN='+self._get_entityid_hostname()) < 0:
                raise EdHostnameNotMatchingCertSubject(
                    'Hostname of entityID (%s) not matching CN in cert subject (%s)' %
                    (self._get_entityid_hostname(), cert.getSubject_str()))

        for cert_pem in self._getCerts('SP'):   # certs in SPSSODescriptor elements
            cert = XY509cert(cert_pem)
            if not cert.isNotExpired():
                raise CertExpiredError('Certificate is expired since ' + cert.notValidAfter() +
                                       '; subject: ' + cert.getSubject_str)
            x509storeContext = crypto.X509StoreContext(self.SP_trustStore.x509store, cert.cert)
            try:
                x509storeContext.verify_certificate()
            except crypto.X509StoreContextError as e:
                raise CertInvalidError(('Certificate validation failed. ' + str(e) + ' ' +
                                        cert.getIssuer_str()))
        logging.debug('Entity certificates valid for ' + self.ed.get_entityid())

    @staticmethod
    def create_delete(entityid) -> str:
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

    @staticmethod
    def _delete_element_if_existing(
            tree: lxml.etree.ElementTree,
            xpath_remove_element: str,
            namespaces: dict):
        if len(tree.xpath(xpath_remove_element, namespaces=namespaces)) > 0:
            remove_elem = tree.xpath(xpath_remove_element, namespaces=namespaces)[0]
            remove_elem.getparent().remove(remove_elem)

    @staticmethod
    def _insert_if_missing(
            tree: lxml.etree.ElementTree,
            xpath_insert_parent: str,
            xpath_new_element: str,
            new_element: lxml.etree.Element,
            namespaces: dict):
        if len(tree.xpath(xpath_new_element, namespaces=namespaces)) == 0:
            parent_element = tree.xpath(xpath_insert_parent, namespaces=namespaces)
            parent_element[0].insert(0, new_element)  # append only for 1st
            pass

    def getAllowedDomainsForOrgs(self, org_ids: list) -> list:
        allowedDomains = []
        for dn in self.policyDict["domain"].keys():
            if self.policyDict["domain"][dn][0] in org_ids:
                allowedDomains.append(dn)
        return allowedDomains

    def _getCerts(self, role) -> list:
        certs = []
        if role == 'IDP': xp = 'md:IDPSSODescriptor//ds:X509Certificate'
        if role == 'SP': xp = 'md:SPSSODescriptor//ds:X509Certificate'
        i = 0
        for elem in self.ed.tree.xpath(xp, namespaces={'ds': XMLNS_DSIG, 'md': XMLNS_MD}):
            certs.append(elem.text)
            i += 1
        return certs

    def get_entityid(self):
        return self.ed.get_entityid()

    def get_filename_from_entityid(self) -> str:
        return self.ed.get_filename_from_entityid()

    def _get_entityid_hostname(self):
        entityID_url = self.ed.get_entityid()
        return urlparse(entityID_url).hostname

    def getOrgIDs(self, signerCert) -> str:
        """ return associated organizations for signer. There are two possible paths:
                signer-cert -> portaladmin -> [orgid]
        """
        try:
            org_ids = self.policyDict["userprivilege"]['{cert}'+signerCert][0]
        except KeyError:
            raise UnauthorizedSignerError('Signer certificate not found in policy directory')
        return org_ids

    def get_xml_str(self):
        return self.ed.get_xml_str()

    def isDeletionRequest(self):
        tree = lxml.etree.parse(self.ed_path)
        rootelem_attr = tree.getroot().attrib
        try:
            return rootelem_attr[XMLNS_PVZD_PREFIX+'disposition'] == 'delete'
        except KeyError:
            return False

    def _isInAllowedDomains(self, dn, allowedDomains) -> bool:
        """  check if dn is identical to or in a wildcard-domain of an allowed domain """
        # TODO: change to explicit wildcards
        parent_dn = re.sub('^[^\.]+\.', '', dn)
        wildcard_dn = '*.' + parent_dn
        if dn in allowedDomains or wildcard_dn in allowedDomains:
            return True
        return False

    #def remove_enveloped_signature(self):
    #    SAMLEntityDescriptorPVP._delete_element_if_existing(self.ed.tree,
    #        '/md:EntityDescriptor/ds:Signature',
    #        {'md': XMLNS_MD, 'ds': XMLNS_DSIG})

    @staticmethod
    def set_registrationinfo(tree, authority, fixed_date_for_unittest=False):
        SAMLEntityDescriptorPVP._delete_element_if_existing(tree,
            '//md:EntityDescriptor/md:Extensions/mdrpi:RegistrationInfo',
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})
        new = lxml.etree.Element(XMLNS_MD_PREFIX + "Extensions")
        SAMLEntityDescriptorPVP._insert_if_missing (tree,
            '//md:EntityDescriptor',
            '//md:EntityDescriptor/md:Extensions',
            new,
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})
        new = lxml.etree.Element(XMLNS_MDRPI_PREFIX + "RegistrationInfo")
        new.set(XMLNS_MDRPI_PREFIX+'registrationAuthority', authority)
        if fixed_date_for_unittest:
            now = datetime(1900, 1, 1, 0, 0, 0, 0)
        else:
            now = datetime.now()
        now_iso8601 = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        new.set(XMLNS_MDRPI_PREFIX+'registrationInstant', now_iso8601)
        SAMLEntityDescriptorPVP._insert_if_missing (tree,
            '//md:EntityDescriptor/md:Extensions',
            '//md:EntityDescriptor/md:Extensions/mdrpi:RegistrationInfo',
            new,
            {'md': XMLNS_MD, 'mdrpi': XMLNS_MDRPI})

    def validateDomainNames(self, allowedDomains) -> bool:
        """ check that entityId and endpoints contain only hostnames from allowed domains"""
        if not self._isInAllowedDomains(self._get_entityid_hostname(), allowedDomains):
            raise InvalidFQDNinEntityID('FQDN of entityID %s not in domains allowed for signer: %s' %
                                        (self._get_entityid_hostname(), sorted(allowedDomains)))
        logging.debug('signer is allowed to use %s as entityID' % self._get_entityid_hostname())
        for attr_value in self.ed.tree.xpath('//md:*/@Location', namespaces={'md': XMLNS_MD}):
            location_hostname = urlparse(attr_value).hostname
            if not self._isInAllowedDomains(location_hostname, allowedDomains):
                raise InvalidFQDNInEndpoint('%s in %s not in allowed domains: %s' %
                                            (location_hostname, attr_value, sorted(allowedDomains)))
            logging.debug('signer is allowed to use %s in %s' % (location_hostname, attr_value))
        return True

    def validate_schematron(self):
        pass  # TODO: implement

    def validateSignature(self) -> str:
        xml_sig_verifyer = XmlSigVerifyer();
        xml_sig_verifyer_response = xml_sig_verifyer.verify(self.ed_path)
        #if self.verbose:
        #    cert = XY509cert(signerCertificateEncoded, inform='DER') # TODO: check encoding
        #    print('Subject CN: ' + cert.getIssuer_str)
        return xml_sig_verifyer_response

    def validate_xsd(self):
        return self.ed.validate_xsd()

    def verify_filename(self):
        """ verify if filename convention maps the entityID. Do _not_ call on object creation """
        basefn = os.path.basename(self.ed_path)
        # file name must have the format "*compressedEntityId.xml". Check right substring:
        if not re.search(str(self.ed.get_filename_from_entityid())+'$', basefn):
            raise InputValueError('Invalid format for EntitiyDescriptor filename "%s". The file name '
                                  'for entityID %s must end with "%s" - see PAtool documentation.' % \
                                  (basefn, self.get_entityid(), self.ed.get_filename_from_entityid()))

    def write(self, new_filename=None):
        fn = self.ed.ed_path if new_filename is None else new_filename
        self.ed.write(fn)

