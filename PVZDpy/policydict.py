import re

from .aodsfilehandler import AODSFileHandler
from .aodslisthandler import AodsListHandler
from .userexceptions import UnauthorizedSignerError

class PolicyDict:
    def __init__(self, invocation=None, policydir=None):
        if not any([invocation, policydir]):
            raise Exception('PolicyDict.__init__ requires either invocation or policydir arg')
        if invocation:
            aodsFileHandler = AODSFileHandler(invocation.args)
            aodsListHandler = AodsListHandler(aodsFileHandler, invocation.args)
            self.policydict = aodsListHandler.aods_read()
        elif policydir:
            self.policydict = policydir

    def getAllowedNamespacesForOrgs(self, org_ids: list) -> list:
        allowedDomains = []
        for dn in self.policydict["domain"].keys():
            if self.policydict["domain"][dn][0] in org_ids:
                allowedDomains.append(dn)
        return allowedDomains

    @staticmethod
    def get_namesp_for_fqdn(fqdn: str, allowed_namespaces: list) -> str:
        if fqdn in allowed_namespaces:
            return fqdn
        parent_fqdn = re.sub('^[^\.]+\.', '', fqdn)
        wildcard_fqdn = '*.' + parent_fqdn
        if wildcard_fqdn in allowed_namespaces:
            return wildcard_fqdn
        else:
            return None

    def get_orgcn(self, orgid) -> str:
        return self.policydict["organization"].get(orgid)[0]

    def get_orgid(self, fqdn) -> str:
        allowed_namespaces = list(self.policydict["domain"].keys())
        namespace = self.get_namesp_for_fqdn(fqdn, allowed_namespaces)
        domain_rec = self.policydict["domain"].get(namespace)
        if domain_rec:
            orgid = domain_rec[0]
            return orgid
        else:
            return None

    def get_orgids_for_signer(self, signerCert) -> str:
        """ return associated organizations for signer.
            The paths is signer-cert -> portaladmin -> [orgid]
        """
        try:
            org_ids = self.policydict["userprivilege"]['{cert}' + signerCert][0]
        except KeyError:
            raise UnauthorizedSignerError('Signer certificate not found in policy directory')
        return org_ids

    def get_policy_dict(self) -> dict:
        return self.poldict


