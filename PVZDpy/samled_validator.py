import lxml.etree
import OpenSSL.crypto
import tempfile

from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.aodslisthandler import AodsListHandler
from PVZDpy.invocation.aodslhinvocation import aodslhInvocation
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.userexceptions import *
from PVZDpy.xy509cert import XY509cert

""" This class parses amd validates a SAMLEntityDescriptorPVP and yields a structured result 
    Supports passing xml as string and file (for PVZDweb and PEP)
    
    For simplicity, xml files are converted to utf-8 strings, and string later back to tempfiles
    for processing with SAMLEntityDescriptorPVP. This will go away if PEP does not read files
    but str from the database
"""

class SamlEdValidator:
    def __init__(self, policydir):
        self._reset_validation_result('')
        self.policydir = policydir
        self.ed_str = ''

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

    def _reset_validation_result(self, ed_str_new):
        self.deletionRequest = None
        self.ed_str = ed_str_new
        self.entityID = ''
        self.orgcn = ''
        self.orgid = ''
        self.signer_cert_cn = ''
        self.signer_cert_pem = ''
        self.val_mesg_dict = {}
        self.val_ok = False

    def _format_val_msg(self, exception, exception_str_edited=None):
        testid_str = ' (test{}) '.format(self.testid) if self.testid else ''
        e_str = exception_str_edited if exception_str_edited else str(exception)
        return '[{}] {}{}'.format(exception.__class__.__name__, testid_str, e_str)

    def validate_entitydescriptor(self, ed_str_new='', ed_path_new='', testid=None):
        self.testid = testid
        if not getattr(self, 'policydir', False):
            self.policydir = self.getPolicyDict_from_json()

        try:
            e = self._get_xml_str(ed_str_new, ed_path_new)
        except(lxml.etree.XMLSyntaxError) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            return

        self._reset_validation_result(e)

        fd = tempfile.NamedTemporaryFile(mode='w', prefix='pvzd_', suffix='.xml')
        fd.write(e)
        fd.flush()

        try:
            self.ed = SAMLEntityDescriptorPVP(fd.name, self.policydir)
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Parse XML'] = self._format_val_msg(e)
            return

        try:
            self.ed.validate_xsd()
            self.entityID = self.ed.get_entityid()
        except(PVZDuserexception) as e:
            msg = str(e)
            fixed_part_pos = msg.find('lineNumber: ')
            fixed_part = msg[fixed_part_pos:]
            self.val_mesg_dict['Validate SAML schema'] = self._format_val_msg(e, fixed_part)

        try:
            self.ed.validate_schematron()
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Validate profile'] = self._format_val_msg(e)

        try:
            xml_sig_verifyer_response = self.ed.validateSignature()
            self.signer_cert_pem = xml_sig_verifyer_response.signer_cert_pem
            self.signer_cert_cn = XY509cert(self.signer_cert_pem).getSubjectCN()
            try:
                org_ids = self.ed.getOrgIDs(xml_sig_verifyer_response.signer_cert_pem)
                allowedDomains = self.ed.getAllowedDomainsForOrgs(org_ids)
                self.ed.validateDomainNames(allowedDomains)
            except(PVZDuserexception) as e:
                self.val_mesg_dict['validate Domain Names'] = self._format_val_msg(e)
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Validate signature'] = self._format_val_msg(e)

        try:
            if self.ed.isDeletionRequest():
                self.deletionRequest = True
            else:
                self.deletionRequest = False
        except(PVZDuserexception) as e:
            self.val_mesg_dict['Deletion request'] = self._format_val_msg(e)

        try:
            self.ed.checkCerts()
        except(OpenSSL.crypto.Error, PVZDuserexception) as e:
            self.val_mesg_dict['Entity certificate check'] = self._format_val_msg(e)
        fd.close()


    def get_obj_as_dict(self):
        return {
            'deletionRequest': self.deletionRequest,
            'entityID': self.entityID,
            'orgcn': self.orgcn,
            'orgid': self.orgid,
            'signer_cert_cn': self.signer_cert_cn,
            'signer_cert_pem': self.signer_cert_pem,
            'val_mesg_dict': self.val_mesg_dict,
            'val_ok': self.val_ok,
        }
