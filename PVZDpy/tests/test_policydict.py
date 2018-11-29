import pytest
#from PVZDpy.constants import *
#from PVZDpy.userexceptions import *
from PVZDpy.policystore import PolicyStore
from PVZDpy.tests.common_fixtures import *


def test_getAllowedNamespacesForOrgs(ed7, namespaces7, orgids7, policydict1):
    allowed_namespaces = policydict1.getAllowedNamespacesForOrgs(orgids7)
    assert namespaces7 == allowed_namespaces


def test_get_namesp_for_fqdn():
    allowed_namespaces =  [
        "*.identinetics.com",
        "some.net",
        "some.org",
        "sp.somenew.org",
    ]
    fqdn1 = 'idp.identinetics.com'
    expected_result1 = '*.identinetics.com'
    assert expected_result1 == PolicyStore.get_namesp_for_fqdn(fqdn1, allowed_namespaces)
    fqdn2 = 'idp.iam.identinetics.com'
    expected_result2 = None  # wildcard MUST NOT match subdomains
    assert expected_result2 == PolicyStore.get_namesp_for_fqdn(fqdn2, allowed_namespaces)
    fqdn3 = 'sp.somenew.org'
    expected_result3 = fqdn3
    assert expected_result3 == PolicyStore.get_namesp_for_fqdn(fqdn3, allowed_namespaces)
    fqdn4 = 'idp.some.net'
    expected_result4 = None
    assert expected_result4 == PolicyStore.get_namesp_for_fqdn(fqdn4, allowed_namespaces)
    fqdn5 = 'idp.some.net'
    expected_result5 = None
    assert expected_result5 == PolicyStore.get_namesp_for_fqdn(fqdn5, {})


def test_get_orgids_for_signer(policydict1, signerCert7):
    orgids = policydict1.get_orgids_for_signer(signerCert7)
    assert ['AT:VKZ:XFN-318886a'] == orgids


def test_get_orgid1(policydict1):
    orgid1 = policydict1.get_orgid('some.fake.hostname')
    assert orgid1 is None


def test_get_orgid7(policydict1):
    orgid7 = policydict1.get_orgid('ipd.identinetics.com')
    assert 'AT:VKZ:XFN-318886a' == orgid7


