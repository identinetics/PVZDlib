import lxml.etree
import OpenSSL.crypto
import tempfile
import enforce
enforce.config({'enabled': True, 'mode': 'covariant'})
from PVZDpy.config.pvzdlib_config_abstract import PVZDlibConfigAbstract
from PVZDpy.constants import EXTRACT_SAMLED_XSLT, TIDY_SAMLED_XSLT
from PVZDpy.policydict import PolicyDict
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.userexceptions import InputValueError, PVZDuserexception
from PVZDpy.xy509cert import XY509cert

""" This class parses and validates a SAMLEntityDescriptorPVP and yields a structured result 
    Supports passing xml as string and file (for PVZDweb and PEP)

    For simplicity, xml files are converted to utf-8 strings, and string later back to tempfiles
    for processing with SAMLEntityDescriptorPVP. This will go away if PEP does not read files
    but str from the database
"""



class NoFurtherValidation(Exception):
    pass


#@enforce.runtime_validation
class SamlEdValidator:
    def __init__(self, policydict: PolicyDict) -> None:
        if not isinstance(policydict, PolicyDict):
            raise Exception('create SamlEdValidator requires PolicyDict')
        self._reset_validation_result()
        self.policydict = policydict
        self.ed_str = ''
        self.schematron_ok = None
        self.certcheck_ok = None

    def _format_val_msg(self, exception: Exception, exception_str_edited: str = None) -> str:
        testid_str = ' (test{}) '.format(self.testid) if self.testid else ''
        e_str = exception_str_edited if exception_str_edited else str(exception)
        return '[{}] {}{}'.format(exception.__class__.__name__, testid_str, e_str)

    def get_obj_as_dict(self):
        return {
            'deletionRequest': self.deletionRequest,
            'entityID': self.entityID,
            'orgcn': self.orgcn,
            'orgid': self.orgid,
            'signer_cert_cn': self.signer_cert_cn,
            'signer_cert_pem': self.signer_cert_pem,
            'val_mesg_dict': self.val_mesg_dict,
            'content_val_ok': self.content_val_ok,
            'authz_ok': self.authz_ok,
        }

    def _get_xml_str(self, ed_str: str = '', ed_path: str = '') -> str:
        if (ed_str and ed_path) or (not ed_str and not ed_path):
            raise InputValueError('one and only one argument out of (ed_str, ed_path) is required')
        if ed_str:
            _ = lxml.etree.fromstring(ed_str.encode('utf-8'))
            return ed_str
        else:
            tree = lxml.etree.parse(ed_path)
            xml_str = lxml.etree.tostring(tree, encoding='utf-8', pretty_print=False)
            return xml_str.decode('utf-8')

    @staticmethod
    def _extract_saml_entitydescriptor(pvzdconf: dict, tree: lxml.etree.ElementTree) -> lxml.etree.ElementTree:
        ''' Make EntityDescriptor the root element (useful if wrapped in EntitiesDescriptor) '''
        xslt = lxml.etree.parse(EXTRACT_SAMLED_XSLT)
        transform = lxml.etree.XSLT(xslt)
        return transform(tree)

    @staticmethod
    def _tidy_saml_entitydescriptor(pvzdconf: dict, tree: lxml.etree.ElementTree) -> lxml.etree.ElementTree:
        xslt = lxml.etree.parse(TIDY_SAMLED_XSLT)
        transform = lxml.etree.XSLT(xslt)
        return transform(tree)

    @staticmethod
    def normalize_ed(xml: bytes) -> bytes:
        ''' convert EntityDescriptor to UTF-8, move namespace declarations to the top,
            remove EntitiesDescriptor root element,
            remove signature/validuntil/cacheduration pretty-print '''
        pvzdconf = PVZDlibConfigAbstract.get_config()
        tree: lxml.etree.ElementTree = lxml.etree.fromstring(xml).getroottree()
        tree: lxml.etree.ElementTree = SamlEdValidator._extract_saml_entitydescriptor(pvzdconf, tree)
        tree: lxml.etree.ElementTree = SamlEdValidator._tidy_saml_entitydescriptor(pvzdconf, tree)
        return lxml.etree.tostring(tree, encoding='UTF-8', xml_declaration=True, pretty_print=True)

    def _reset_validation_result(self) -> None:
        self.deletionRequest = None
        self.ed_str = ''
        self.entityID = ''
        self.orgcn = ''
        self.orgid = ''
        self.signer_cert_cn = ''
        self.signer_cert_pem = ''
        self.val_mesg_dict = {}
        self.content_val_ok = None
        self.authz_ok = None

    def validate_entitydescriptor(
            self,
            ed_str_new: str = '',
            ed_path_new: str = '',
            portaladmin_sigval: bool = True,
            keydesc_certval: bool = True,
            testid: bool = None) -> None:
        self.testid = testid
        self._reset_validation_result()
        if not getattr(self, 'policydict', False):
            self.policydict = self.policydict.get_policydict()
        try:
            self._validate_parse_xml(ed_str_new, ed_path_new)
            self._create_tempfile_from_edstr()
            self._validate_instantiate_ed()
            self._validate_xsd()
            self.entityID = self.ed.get_entityid()
            self._validate_saml_profile()
            self.deletionRequest = self.ed.isDeletionRequest()
            if keydesc_certval:
                self._validate_keydesc_certs()
            else:
                self.certcheck_ok = True
            self.content_val_ok = self.schematron_ok and self.certcheck_ok
            self._validate_is_registered_namespace()
            if portaladmin_sigval:
                self._validate_authz()
            self._discard_tempfile()
        except NoFurtherValidation:
            pass

    def _validate_parse_xml(self, ed_str_new: str, ed_path_new: str) -> None:
        try:
            self.ed_str = self._get_xml_str(ed_str_new, ed_path_new)
        except(lxml.etree.XMLSyntaxError) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            raise NoFurtherValidation

    def _create_tempfile_from_edstr(self) -> None:
        # make xml available for lxml file parsing (to avoid encoding issues)
        self.fd = tempfile.NamedTemporaryFile(mode='w', prefix='pvzd_', suffix='.xml', encoding='utf-8')
        self.fd.write(self.ed_str)
        self.fd.flush()

    def _discard_tempfile(self) -> None:
        self.fd.close()

    def _validate_instantiate_ed(self) -> None:
        try:
            self.ed = SAMLEntityDescriptorPVP(self.fd.name, self.policydict)
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            raise NoFurtherValidation

    def _validate_xsd(self) -> None:
        try:
            self.ed.validate_xsd()
        except(PVZDuserexception) as e:
            msg = str(e)
            fixed_part_pos = msg.find('lineNumber: ')
            fixed_part = msg[fixed_part_pos:]
            self.val_mesg_dict['SAML XML schema'] = self._format_val_msg(e, fixed_part)
            raise NoFurtherValidation

    def _validate_saml_profile(self) -> None:
        try:
            self.ed.validate_schematron()
            self.schematron_ok = True
        except(PVZDuserexception) as e:
            self.schematron_ok = False
            self.val_mesg_dict['Validate profile'] = self._format_val_msg(e)

    def _validate_keydesc_certs(self) -> None:
        try:
            if self.ed.isDeletionRequest():
                self.certcheck_ok = True
            else:
                self.ed.checkCerts()
                self.certcheck_ok = True
        except(OpenSSL.crypto.Error, PVZDuserexception) as e:
            self.certcheck_ok = False
            self.val_mesg_dict['Entity cert'] = self._format_val_msg(e)

    def _validate_is_registered_namespace(self) -> None:
        fqdn = self.ed.get_entityid_hostname()
        if not self.ed.isInRegisteredNamespaces(fqdn):
            self.val_mesg_dict['Hostname'] = fqdn + ' is not registered with anybody'

    def _validate_authz(self) -> None:
        try:
            xml_sig_verifyer_response = self.ed.validateSignature()
            self.signer_cert_pem = xml_sig_verifyer_response.signer_cert_pem
            self.signer_cert_cn = XY509cert(self.signer_cert_pem).getSubjectCN()
            if len(self.ed.get_entityid_hostname()) == 0:
                self.authz_ok = False
                self.val_mesg_dict['Hostname'] = 'Cannot authorize: no hostname found when URL-parsing entityID'
                raise NoFurtherValidation
            try:
                org_ids = self.policydict.get_orgids_for_signer(xml_sig_verifyer_response.signer_cert_pem)
                allowedDomains = self.policydict.getAllowedNamespacesForOrgs(org_ids)
                self.ed.validateDomainNames(allowedDomains)
                self.orgid = self.policydict.get_orgid(self.ed.get_entityid_hostname())
                self.orgcn = self.policydict.get_orgcn(self.orgid)
                self.authz_ok = True
            except(PVZDuserexception) as e:
                self.authz_ok = False
                self.val_mesg_dict['Hostname'] = self._format_val_msg(e)
        except(PVZDuserexception) as e:
            self.authz_ok = False
            self.val_mesg_dict['Validate signature'] = self._format_val_msg(e)
