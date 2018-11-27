import json
import lxml.etree
import pytest
import tempfile
from PVZDpy.constants import *
from PVZDpy.userexceptions import *
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.tests.common_fixtures import *


def assert_equal(expected, actual, fn=''):
    # workaround because pycharm does not display the full string (despite pytest -vv etc)
    msg = fn+"\n'"+actual+"' != '"+expected+"' "
    assert expected == actual, msg


@pytest.fixture
def namespaces7():
    return ['*.identinetics.com']

@pytest.fixture
def orgids7():
    return ['AT:VKZ:XFN-318886a']

@pytest.fixture
def signerCert7():
    with open(path_prefix_testin+'signercert7_rh.pem') as fd:
        return fd.read()

@pytest.fixture
def ed(file_index: int):
    return SAMLEntityDescriptorPVP(ed_path(file_index), poldir1())


def test_checkCerts():
    ed(1).checkCerts()
    with pytest.raises(CertInvalidError):
        ed(2).checkCerts()
    with pytest.raises(CertInvalidError):
        ed(5).checkCerts()
    with pytest.raises(CertExpiredError):
        ed(12).checkCerts()
    ed(6).checkCerts()
    with pytest.raises(MultipleEntitiesNotAllowed):
        ed(13).checkCerts()
    with pytest.raises(EdHostnameNotMatchingCertSubject):
        ed(14).checkCerts()


def test_create_delete():
    delete_requ = SAMLEntityDescriptorPVP.create_delete('https://idp4.example.com/idp.xml')
    with open(ed_path(4)) as fd:
        assert_equal(fd.read(), delete_requ)


def test_getAllowedNamespacesForOrgs():
    allowed_namespaces = ed(7).getAllowedNamespacesForOrgs(orgids7())
    assert namespaces7() == allowed_namespaces


def test_get_namespace():
    ed1 = ed(1)
    assert ed1.get_namespace() is None
    ed7 = ed(7)
    assert '*.identinetics.com' == ed7.get_namespace()


def test_get_namesp_for_fqdn():
    allowed_namespaces =  [
        "*.identinetics.com",
        "some.net",
        "some.org",
        "sp.somenew.org",
    ]
    fqdn1 = 'idp.identinetics.com'
    expected_result1 = '*.identinetics.com'
    assert expected_result1 == SAMLEntityDescriptorPVP.get_namesp_for_fqdn(fqdn1, allowed_namespaces)
    fqdn2 = 'idp.iam.identinetics.com'
    expected_result2 = None  # wildcard MUST NOT match subdomains
    assert expected_result2 == SAMLEntityDescriptorPVP.get_namesp_for_fqdn(fqdn2, allowed_namespaces)
    fqdn3 = 'sp.somenew.org'
    expected_result3 = fqdn3
    assert expected_result3 == SAMLEntityDescriptorPVP.get_namesp_for_fqdn(fqdn3, allowed_namespaces)
    fqdn4 = 'idp.some.net'
    expected_result4 = None
    assert expected_result4 == SAMLEntityDescriptorPVP.get_namesp_for_fqdn(fqdn4, allowed_namespaces)
    fqdn5 = 'idp.some.net'
    expected_result5 = None
    assert expected_result5 == SAMLEntityDescriptorPVP.get_namesp_for_fqdn(fqdn5, {})


def test_isInAllowedNamespaces():
    allowed_namespaces =  {
        "*.identinetics.com": ["AT:VKZ:XFN-318886a"],
        "some.net": ["AT:VKZ:XZVR:4711"],
        "some.org": ["AT:VKZ:XZVR:4711"],
        "sp.somenew.org": ["AT:VKZ:XZVR:4712"]
    }
    fqdn1 = 'idp.identinetics.com'
    assert SAMLEntityDescriptorPVP.isInAllowedNamespaces(fqdn1, allowed_namespaces)
    fqdn2 = 'idp.iam.identinetics.com'
    assert not SAMLEntityDescriptorPVP.isInAllowedNamespaces(fqdn2, allowed_namespaces)
    fqdn3 = 'sp.somenew.org'
    assert SAMLEntityDescriptorPVP.isInAllowedNamespaces(fqdn3, allowed_namespaces)
    fqdn4 = 'idp.some.net'
    assert not SAMLEntityDescriptorPVP.isInAllowedNamespaces(fqdn4, allowed_namespaces)
    fqdn5 = 'idp.some.net'
    assert not SAMLEntityDescriptorPVP.isInAllowedNamespaces(fqdn5, {})


def test_isInRegisteredNamespaces():
    fqdn1 = 'idp.identinetics.com'
    assert ed(1).isInRegisteredNamespaces(fqdn1)
    fqdn2 = 'idp.iam.identinetics.com'
    assert not ed(1).isInRegisteredNamespaces(fqdn2)
    fqdn3 = 'sp.somenew.org'
    assert not ed(1).isInRegisteredNamespaces(fqdn3)
    fqdn4 = 'idp.some.net'
    assert not ed(1).isInRegisteredNamespaces(fqdn4)
    fqdn5 = 'idp.some.net'
    assert not ed(1).isInRegisteredNamespaces(fqdn5)


def test_get_orgids_for_signer():
    orgids = ed(2).get_orgids_for_signer(signerCert7())
    assert ['AT:VKZ:XFN-318886a'] == orgids


def test_get_orgid():
    orgid1 = ed(1).get_orgid()
    assert orgid1 is None
    orgid7 = ed(7).get_orgid()
    assert 'AT:VKZ:XFN-318886a' == orgid7


def test_isDeletionRequest():
    assert not ed(2).isDeletionRequest()
    assert ed(4).isDeletionRequest()


def test_remove_enveloped_signature():
    ed10 = ed(10)
    ed10.remove_enveloped_signature()
    fn10_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test10_edit', suffix='.xml').name
    ed10.write(fn10_edit)
    with open(ed_path(17)) as fd17:
        with open(fn10_edit) as fn10_edit:
            assert_equal(fd17.read(), fn10_edit.read(), fn=fn10_edit.name)


def test_set_registrationinfo():
    ed1=ed(1)
    # make expected equal to actual with fake registrationInstant = "1900-01-01T00:00:00Z"
    SAMLEntityDescriptorPVP.set_registrationinfo(ed1.ed.tree, SAML_MDPRI_REGISTRATIONAUTHORITY, fixed_date_for_unittest=True)
    fn1_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test1_edit', suffix='xml').name
    ed1.write(fn1_edit)
    with open(ed_path(16)) as fd2:
        with open(fn1_edit) as fd1:
            assert_equal(fd2.read(), fd1.read())
    os.unlink(fn1_edit)


def test_validate_schematron():
    ed(2).validate_schematron()


def test_validate_xsd():
    ed(2).validate_xsd()
    with pytest.raises(lxml.etree.XMLSyntaxError):
        ed(8).validate_xsd()
    with pytest.raises(InvalidSamlXmlSchemaError):
        ed(9).validate_xsd()


def test_validateDomainNames():
    with pytest.raises(InvalidFQDNinEntityID):
        ed(1).validateDomainNames(namespaces7())
    ed(7).validateDomainNames(namespaces7())
    with pytest.raises(InvalidFQDNInEndpoint):
        ed(15).validateDomainNames(namespaces7())


def test_validateSignature():
    with pytest.raises(ValidationError):
        ed(1).validateSignature()
    ed(10).validateSignature()
    ed(11).validateSignature()


def test_verify_filename():
    with pytest.raises(InputValueError):
        ed(2).verify_filename()
    ed(0).verify_filename()


#def test_write():
#   test included by test_remove_enveloped_signature

