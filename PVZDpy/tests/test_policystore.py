import json
from os.path import join as opj
import pytest
#from PVZDpy.constants import *
#from PVZDpy.userexceptions import *
from ..policystore import PolicyStore
from .common_fixtures import *

path_prefix_testin = opj('testdata', 'policystore')

def assert_equal(expected, actual, fn=''):
    # workaround because pycharm does not display the full string (despite pytest -vv etc)
    msg = fn+"\n'"+actual+"' != '"+expected+"' "
    assert expected == actual, msg

@pytest.fixture
def policystore1_issuers():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_issuers.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policystore1_namespaces():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_namespaces.json')) as fd:
        return fd.read()


@pytest.fixture
def policystore1_namespace_obj():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_namespace_obj.json')) as fd:
        return fd.read()


@pytest.fixture
def policystore1_orgs():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_orgs.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policystore1_revoked_certs():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_revoked_certs.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policystore1_userprivileges():
    with open(opj(path_prefix_testin, 'expected_results', 'policystore1_userprivileges.json')) as fd:
        return json.loads(fd.read())


def test_getAllowedNamespacesForOrgs(ed7, namespaces7, orgids7, policystore1):
    allowed_namespaces = policystore1.getAllowedNamespacesForOrgs(orgids7)
    assert namespaces7 == allowed_namespaces


def test_get_all_orgids(policystore1, policystore1_orgs):
    org_recs = policystore1.get_all_orgids()
    assert policystore1_orgs == org_recs


def test_get_issuers(policystore1, policystore1_issuers):
    r_recs = policystore1.get_issuers()
    assert policystore1_issuers == r_recs


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


def test_get_orgids_for_signer(policystore1, signerCert7):
    orgids = policystore1.get_orgids_for_signer(signerCert7)
    assert ['AT:VKZ:XFN-318886a'] == orgids


def test_get_orgid1(policystore1):
    orgid1 = policystore1.get_orgid('some.fake.hostname')
    assert orgid1 is None


def test_get_orgid7(policystore1):
    orgid7 = policystore1.get_orgid('ipd.identinetics.com')
    assert 'AT:VKZ:XFN-318886a' == orgid7


def test_get_orgcn0(policystore1):
    orgcn0 = policystore1.get_orgcn(None)
    assert orgcn0 == ''


def test_get_registered_namespaces(policystore1, policystore1_namespaces):
    ns_names = policystore1.get_registered_namespaces()
    assert policystore1_namespaces == json.dumps(ns_names, sort_keys=True)


def test_get_registered_namespace_objs(policystore1, policystore1_namespace_obj):
    ns_recs = policystore1.get_registered_namespace_objs()
    json_str = json.dumps(ns_recs, sort_keys=True, indent=2)
    assert policystore1_namespace_obj == json_str


def test_get_revoked_certs(policystore1, policystore1_revoked_certs):
    r_recs = policystore1.get_revoked_certs()
    assert policystore1_revoked_certs == r_recs


def test_get_userprivileges(policystore1, policystore1_userprivileges):
    u_recs = policystore1.get_userprivileges()
    assert policystore1_userprivileges == u_recs
