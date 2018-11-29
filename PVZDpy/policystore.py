import re

from .aodsfilehandler import AODSFileHandler
from .aodslisthandler import AodsListHandler
from .userexceptions import UnauthorizedSignerError

class PolicyStore:
    def __init__(self, invocation=None, policydir=None):
        if not any([invocation, policydir]):
            raise Exception('PolicyStore.__init__ requires either invocation or policydir arg')
        if invocation:
            aodsFileHandler = AODSFileHandler(invocation.args)
            aodsListHandler = AodsListHandler(aodsFileHandler, invocation.args)
            self._policydir = aodsListHandler.aods_read()
        elif policydir:
            self._policydir = policydir

    def getAllowedNamespacesForOrgs(self, org_ids: list) -> list:
        allowedDomains = []
        for dn in self._policydir["domain"].keys():
            if self._policydir["domain"][dn][0] in org_ids:
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
        return self._policydir["organization"].get(orgid)[0]

    def get_orgid(self, fqdn) -> str:
        allowed_namespaces = list(self._policydir["domain"].keys())
        namespace = self.get_namesp_for_fqdn(fqdn, allowed_namespaces)
        domain_rec = self._policydir["domain"].get(namespace)
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
            org_ids = self._policydir["userprivilege"]['{cert}' + signerCert][0]
        except KeyError:
            raise UnauthorizedSignerError('Signer certificate not found in policy directory')
        return org_ids

    def get_policydir(self) -> dict:
        return self._policydir


