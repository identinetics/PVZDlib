import lxml.etree
import OpenSSL.crypto
import tempfile

from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.aodslisthandler import AodsListHandler
from PVZDpy.invocation.aodslhinvocation import aodslhInvocation
from PVZDpy.policystore import PolicyStore
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.userexceptions import *
from PVZDpy.xy509cert import XY509cert

""" This class parses amd validates a SAMLEntityDescriptorPVP and yields a structured result 
    Supports passing xml as string and file (for PVZDweb and PEP)
    
    For simplicity, xml files are converted to utf-8 strings, and string later back to tempfiles
    for processing with SAMLEntityDescriptorPVP. This will go away if PEP does not read files
    but str from the database
"""

class NoFurtherValidation(Exception):
    pass

class SamlEdValidator:
    def __init__(self, policystore: PolicyStore):
        if not isinstance(policystore, PolicyStore):
            raise exception('create SamlEdValidator requires PolicyStore')
        self._reset_validation_result()
        self.policystore = policystore
        self.ed_str = ''
        self.schematron_ok = None
        self.certcheck_ok = None

    def _format_val_msg(self, exception, exception_str_edited=None):
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

    def _get_xml_str(self, ed_str='', ed_path='') -> str:
        if (ed_str and ed_path) or (not ed_str and not ed_path):
            raise InputValueError('one and only one argument out of (ed_str, ed_path) is required')
        if ed_str:
            _ = lxml.etree.fromstring(ed_str.encode('utf-8'))
            return ed_str
        else:
            tree = lxml.etree.parse(ed_path)
            xml_str = lxml.etree.tostring(tree, encoding='utf-8', pretty_print=False)
            return xml_str.decode('utf-8')

    def _reset_validation_result(self):
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

    def validate_entitydescriptor(self, ed_str_new='', ed_path_new='', sigval=True, testid=None):
        self.testid = testid
        self._reset_validation_result()
        if not getattr(self, 'policydir', False):
            self.policydir = self.policystore.get_policydir()
        try:
            self._validate_parse_xml(ed_str_new, ed_path_new)
            self._create_tempfile_from_edstr()
            self._validate_instantiate_ed()
            self._validate_xsd()
            self.entityID = self.ed.get_entityid()
            self._validate_saml_profile()
            self.deletionRequest = self.ed.isDeletionRequest()
            self._validate_certcheck()
            self.content_val_ok = self.schematron_ok and self.certcheck_ok
            self._validate_is_registered_namespace()
            if sigval:
                self._validate_authz()
            self._discard_tempfile()
        except NoFurtherValidation:
            pass


    def _validate_parse_xml(self, ed_str_new, ed_path_new):
        try:
            self.ed_str = self._get_xml_str(ed_str_new, ed_path_new)
        except(lxml.etree.XMLSyntaxError) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            raise NoFurtherValidation

    def _create_tempfile_from_edstr(self):
        # make xml available for lxml file parsing (to avoid encoding issues)
        self.fd = tempfile.NamedTemporaryFile(mode='w', prefix='pvzd_', suffix='.xml')
        self.fd.write(self.ed_str)
        self.fd.flush()

    def _discard_tempfile(self):
        self.fd.close()

    def _validate_instantiate_ed(self):
        try:
            self.ed = SAMLEntityDescriptorPVP(self.fd.name, self.policystore)
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            raise NoFurtherValidation

    def _validate_xsd(self):
        try:
            self.ed.validate_xsd()
        except(PVZDuserexception) as e:
            msg = str(e)
            fixed_part_pos = msg.find('lineNumber: ')
            fixed_part = msg[fixed_part_pos:]
            self.val_mesg_dict['SAML XML schema'] = self._format_val_msg(e, fixed_part)
            raise NoFurtherValidation

    def _validate_saml_profile(self):
        try:
            self.ed.validate_schematron()
            self.schematron_ok = True
        except(PVZDuserexception) as e:
            self.schematron_ok = False
            self.val_mesg_dict['Validate profile'] = self._format_val_msg(e)

    def _validate_certcheck(self):
        try:
            if  self.ed.isDeletionRequest():
                self.certcheck_ok = True
            else:
                self.ed.checkCerts()
                self.certcheck_ok = True
        except(OpenSSL.crypto.Error, PVZDuserexception) as e:
            self.certcheck_ok = False
            self.val_mesg_dict['Entity cert'] = self._format_val_msg(e)

    def _validate_is_registered_namespace(self):
        fqdn = self.ed.get_entityid_hostname()
        if not self.ed.isInRegisteredNamespaces(fqdn):
            self.val_mesg_dict['Hostname'] = fqdn + ' is not registered with anybody'

    def _validate_authz(self):
        try:
            xml_sig_verifyer_response = self.ed.validateSignature()
            self.signer_cert_pem = xml_sig_verifyer_response.signer_cert_pem
            self.signer_cert_cn = XY509cert(self.signer_cert_pem).getSubjectCN()
            if len(self.ed.get_entityid_hostname()) == 0:
                self.authz_ok = False
                self.val_mesg_dict['Hostname'] = 'Cannot authorize: no hostname found when URL-parsing entityID'
                raise NoFurtherValidation
            try:
                org_ids = self.policystore.get_orgids_for_signer(xml_sig_verifyer_response.signer_cert_pem)
                allowedDomains = self.policystore.getAllowedNamespacesForOrgs(org_ids)
                self.ed.validateDomainNames(allowedDomains)
                self.orgid = self.policystore.get_orgid(self.ed.get_entityid_hostname())
                self.orgcn = self.policystore.get_orgcn(self.orgid)
                self.authz_ok = True
            except(PVZDuserexception) as e:
                self.authz_ok = False
                self.val_mesg_dict['Hostname'] = self._format_val_msg(e)
        except(PVZDuserexception) as e:
            self.authz_ok = False
            self.val_mesg_dict['Validate signature'] = self._format_val_msg(e)

