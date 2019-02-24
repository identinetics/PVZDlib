import re

from PVZDpy.aodslisthandler import AodsListHandler
from PVZDpy.policychange import PolicyChangeList, PolicyChangeOrganization
from PVZDpy.userexceptions import UnauthorizedSignerError


class OrgDict:
    """ Auxiliary class to pass around a list of organizations """
    def __init__(self):
        self._orgs = {}

    def append(self, gvouid: str, cn: str) -> None:
        assert gvouid
        assert cn
        self._orgs[gvouid] = cn

    def get_orgs(self) -> dict:
        return self._orgs

    def exists(self, gvouid: str) -> bool:
        return gvouid in self._orgs.keys()


class PolicyDict:
    ''' provide high-level API to policy store '''
    def __init__(self, test_policydict: dict=None):
        if test_policydict:
            self._policydict = test_policydict
        else:
            aodsListHandler = AodsListHandler()
            self._policydict = aodsListHandler.read()

    def getAllowedNamespacesForOrgs(self, org_ids: list) -> list:
        allowedDomains = []
        for dn in self._policydict["domain"].keys():
            if self._policydict["domain"][dn][0] in org_ids:
                allowedDomains.append(dn)
        return allowedDomains

    def get_issuers(self):
        return self._policydict["issuer"]

    @staticmethod
    def get_namesp_for_fqdn(fqdn: str, allowed_namespaces: list) -> str:
        if fqdn in allowed_namespaces:
            return fqdn
        parent_fqdn = re.sub(r'^[^\.]+\.', '', fqdn)
        wildcard_fqdn = '*.' + parent_fqdn
        if wildcard_fqdn in allowed_namespaces:
            return wildcard_fqdn
        else:
            return None

    def get_orgcn(self, orgid) -> str:
        try:
            return self._policydict["organization"].get(orgid)[0]
        except Exception:
            return ''

    def get_orgid(self, fqdn) -> str:
        allowed_namespaces = list(self._policydict["domain"].keys())
        namespace = self.get_namesp_for_fqdn(fqdn, allowed_namespaces)
        domain_rec = self._policydict["domain"].get(namespace)
        if domain_rec:
            orgid = domain_rec[0]
            return orgid
        else:
            return None

    def get_all_orgids(self) -> list:
        org_recs = self._policydict["organization"]
        return org_recs

    def get_org_sync_changelist(self, orgs: OrgDict) -> PolicyChangeList:
        ''' compare the passed list of organizations with the current policy dict
            and return the list of add and delete records to sync the journal
        '''
        def get_inputrec(gvouid, cn, delete=None) -> dict:
            return PolicyChangeOrganization(gvouid, cn, delete)

        def append_missing_items():
            for gvouid in orgs.get_orgs().keys():
                if gvouid not in poldict_gvouids:
                    cn = self.get_orgcn(gvouid)
                    org_changelist.append(get_inputrec(gvouid, cn, delete=False))

        def append_orphan_items():
            for gvouid in sorted(poldict_gvouids):  # need stable order for unit test
                if not orgs.exists(gvouid):
                    cn = self.get_orgcn(gvouid)
                    org_changelist.append(get_inputrec(gvouid, cn, delete=True))

        poldict_gvouids = set(self.get_all_orgids().keys())
        org_changelist = PolicyChangeList()
        append_missing_items()
        append_orphan_items()
        return org_changelist

    def get_issuers(self):
        return self._policydict["issuer"]

    def get_orgids_for_signer(self, signerCert) -> list:
        """ return associated organizations for signer.
            The paths is signer-cert -> portaladmin -> [orgid]
        """
        try:
            org_ids = self._policydict["userprivilege"]['{cert}' + signerCert][0]
        except KeyError:
            raise UnauthorizedSignerError('Signer certificate not found in policy directory')
        return org_ids

    def get_policydict(self) -> dict:
        return self._policydict

    def get_registered_namespaces(self) -> list:
        return sorted(list(self._policydict["domain"].keys()))

    def get_registered_namespace_objs(self) -> list:
        return self._policydict["domain"]

    def get_revoked_certs(self) -> list:
        return sorted(list(self._policydict["revocation"].keys()))

    def get_userprivileges(self):
        return self._policydict["userprivilege"]
