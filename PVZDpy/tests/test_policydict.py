import json
from os.path import join as opj
import pytest
from PVZDpy.policydict import OrgDict, PolicyDict
from PVZDpy.tests.common_fixtures import *

path_prefix_testin = opj('testdata', 'policydict')

def assert_equal(expected, actual, fn=''):
    # workaround because pycharm does not display the full string (despite pytest -vv etc)
    msg = fn+"\n'"+actual+"' != '"+expected+"' "
    assert expected == actual, msg

@pytest.fixture
def policydict1_issuers():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_issuers.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policydict1_namespaces():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_namespaces.json')) as fd:
        return fd.read()


@pytest.fixture
def policydict1_namespace_obj():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_namespace_obj.json')) as fd:
        return fd.read()


@pytest.fixture
def policydict1_orgs():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_orgs.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policydict1_revoked_certs():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_revoked_certs.json')) as fd:
        return json.loads(fd.read())


@pytest.fixture
def policydict1_userprivileges():
    with open(opj(path_prefix_testin, 'expected_results', 'policydict1_userprivileges.json')) as fd:
        return json.loads(fd.read())


def test_getAllowedNamespacesForOrgs(ed7, namespaces7, orgids7, policydict1):
    allowed_namespaces = policydict1.getAllowedNamespacesForOrgs(orgids7)
    assert namespaces7 == allowed_namespaces


def test_get_all_orgids(policydict1, policydict1_orgs):
    org_recs = policydict1.get_all_orgids()
    assert policydict1_orgs == org_recs


def test_get_issuers(policydict1, policydict1_issuers):
    r_recs = policydict1.get_issuers()
    assert policydict1_issuers == r_recs


def test_get_namesp_for_fqdn():
    allowed_namespaces =  [
        "*.identinetics.com",
        "some.net",
        "some.org",
        "sp.somenew.org",
    ]
    fqdn1 = 'idp.identinetics.com'
    expected_result1 = '*.identinetics.com'
    assert expected_result1 == PolicyDict.get_namesp_for_fqdn(fqdn1, allowed_namespaces)
    fqdn2 = 'idp.iam.identinetics.com'
    expected_result2 = None  # wildcard MUST NOT match subdomains
    assert expected_result2 == PolicyDict.get_namesp_for_fqdn(fqdn2, allowed_namespaces)
    fqdn3 = 'sp.somenew.org'
    expected_result3 = fqdn3
    assert expected_result3 == PolicyDict.get_namesp_for_fqdn(fqdn3, allowed_namespaces)
    fqdn4 = 'idp.some.net'
    expected_result4 = None
    assert expected_result4 == PolicyDict.get_namesp_for_fqdn(fqdn4, allowed_namespaces)
    fqdn5 = 'idp.some.net'
    expected_result5 = None
    assert expected_result5 == PolicyDict.get_namesp_for_fqdn(fqdn5, {})


def test_get_orgids_for_signer(policydict1, signerCert7):
    orgids = policydict1.get_orgids_for_signer(signerCert7)
    assert ['AT:VKZ:XFN-318886a'] == orgids


def test_get_orgid1(policydict1):
    orgid1 = policydict1.get_orgid('some.fake.hostname')
    assert orgid1 is None


def test_get_orgid7(policydict1):
    orgid7 = policydict1.get_orgid('ipd.identinetics.com')
    assert 'AT:VKZ:XFN-318886a' == orgid7


def test_get_orgcn0(policydict1):
    orgcn0 = policydict1.get_orgcn(None)
    assert orgcn0 == ''


def test_get_registered_namespaces(policydict1, policydict1_namespaces):
    ns_names = policydict1.get_registered_namespaces()
    assert policydict1_namespaces == json.dumps(ns_names, sort_keys=True)


def test_get_registered_namespace_objs(policydict1, policydict1_namespace_obj):
    ns_recs = policydict1.get_registered_namespace_objs()
    json_str = json.dumps(ns_recs, sort_keys=True, indent=2)
    assert policydict1_namespace_obj == json_str


def test_get_revoked_certs(policydict1, policydict1_revoked_certs):
    r_recs = policydict1.get_revoked_certs()
    assert policydict1_revoked_certs == r_recs


def test_get_userprivileges(policydict1, policydict1_userprivileges):
    u_recs = policydict1.get_userprivileges()
    assert policydict1_userprivileges == u_recs


def test_get_org_sync_changelist(policydict1):
    def _run_test(new_orgs: dict, expected_result):
        new_orgdict = OrgDict()
        for gvouid, cn in new_orgs.items():
            new_orgdict.append(gvouid, cn)
        org_changelist = policydict1.get_org_sync_changelist(new_orgdict)
        assert org_changelist.dict2list_for_compare() == expected_result

    # case 1: no diff; case2: add item; case 3: delete two items
    for i in (1, 2, 3):
        with open(opj(path_prefix_testin, 'new_orglist{}.json'.format(i))) as fd:
            new_orgdict = json.load(fd)
            with open(opj(path_prefix_testin, 'expected_results', 'org_sync_changelist{}.json'.format(i))) as fd:
                expected_result = json.load(fd)
                _run_test(new_orgdict, expected_result)