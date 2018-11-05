from PVZDpy.aodsfilehandler import AODSFileHandler
from PVZDpy.invocation.aodsfhinvocation import aodsfhInvocation
from PVZDpy.aodslisthandler import AodsListHandler
from PVZDpy.invocation.aodslhinvocation import aodslhInvocation
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.userexceptions import *

class EdValidator:
    def __init__(self):
        self.ed_previous = ''
        self.entityID = ''
        self.orgid = ''
        self.orgcn = ''
        self.signer_cert_pem = ''
        self.signer_cert_cn = ''
        self.ed_validated = False

    def validate_entitydescriptor(self, ed):
        """ validate EntityDescriptorPVP; """  # TODO: try to reuse cached results
        if ed == self.ed_previous:
            return

        if self.ed_validated:
            return

        if not getattr(self, 'policydir', False):
            self.policydir = self.getPolicyDict_from_json()
        fd = tempfile.NamedTemporaryFile(mode='w', prefix='pvzd_', suffix='.xml')
        fd.write(self.ed_uploaded)
        fd.flush()
        self.entityID = 'EntityDescriptor ungültig'
        self.validation_ok = False
        try:
            self.ed = SAMLEntityDescriptorPVP(fd.name, self.policydir)
            self.entityID = self.ed.get_entityid()
            self.ed.validate_xsd()
            self.ed.validate_schematron()
            xml_sig_verifyer_response = self.ed.validateSignature()
            org_ids = self.ed.getOrgIDs(xml_sig_verifyer_response.signer_cert_pem)
            allowedDomains = self.ed.getAllowedDomainsForOrgs(org_ids)
            self.ed.validateDomainNames(allowedDomains)
            if self.ed.isDeletionRequest():
                self.DeletionRequest = True
            else:
                self.DeletionRequest = False
                self.ed.checkCerts()
            self.validation_msg = ''
            self.validation_ok = True
        except(Exception) as e:
            self.validation_msg = '[{}] {}'.format(e.__class__.__name__, str(e))
        fd.close()


