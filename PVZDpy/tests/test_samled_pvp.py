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



def test_checkCerts1(ed1):
    ed1.checkCerts()

def test_checkCerts2(ed2):
    with pytest.raises(CertInvalidError):
        ed2.checkCerts()

def test_checkCerts5(ed5):
    with pytest.raises(CertInvalidError):
        ed5.checkCerts()

def test_checkCerts6(ed6):
    ed6.checkCerts()

def test_checkCerts12(ed12):
    with pytest.raises(CertExpiredError):
        ed12.checkCerts()

def test_checkCerts13(policystore1):
    with pytest.raises(MultipleEntitiesNotAllowed):
        ed13 = SAMLEntityDescriptorPVP(ed_path(13), policystore1)

def test_checkCerts14(ed14):
    with pytest.raises(EdHostnameNotMatchingCertSubject):
        ed14.checkCerts()


def test_create_delete():
    delete_requ = SAMLEntityDescriptorPVP.create_delete('https://idp4.example.com/idp.xml')
    with open(ed_path(4)) as fd:
        assert_equal(fd.read(), delete_requ)


def test_get_namespace1(ed1):
    assert ed1.get_namespace() is None

def test_get_namespace1(ed7):
    assert '*.identinetics.com' == ed7.get_namespace()


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


def test_isInRegisteredNamespaces(ed1):
    fqdn1 = 'idp.identinetics.com'
    assert ed1.isInRegisteredNamespaces(fqdn1)
    fqdn2 = 'idp.iam.identinetics.com'
    assert not ed1.isInRegisteredNamespaces(fqdn2)
    fqdn3 = 'sp.somenew.org'
    assert not ed1.isInRegisteredNamespaces(fqdn3)
    fqdn4 = 'idp.some.net'
    assert not ed1.isInRegisteredNamespaces(fqdn4)
    fqdn5 = 'idp.some.net'
    assert not ed1.isInRegisteredNamespaces(fqdn5)


def test_isDeletionRequest2(ed2):
    assert not ed2.isDeletionRequest()

def test_isDeletionRequest4(ed4):
    assert ed4.isDeletionRequest()


def test_remove_enveloped_signature(ed10):
    ed10.remove_enveloped_signature()
    fn10_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test10_edit', suffix='.xml').name
    ed10.write(fn10_edit)
    with open(ed_path(17)) as fd17:
        with open(fn10_edit) as fn10_edit:
            assert_equal(fd17.read(), fn10_edit.read(), fn=fn10_edit.name)


def test_set_registrationinfo(ed1):
    # make expected equal to actual with fake registrationInstant = "1900-01-01T00:00:00Z"
    SAMLEntityDescriptorPVP.set_registrationinfo(ed1.ed.tree, SAML_MDPRI_REGISTRATIONAUTHORITY, fixed_date_for_unittest=True)
    fn1_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test1_edit', suffix='xml').name
    ed1.write(fn1_edit)
    with open(ed_path(16)) as fd2:
        with open(fn1_edit) as fd1:
            assert_equal(fd2.read(), fd1.read())
    os.unlink(fn1_edit)


def test_validate_schematron(ed2):
    ed2.validate_schematron()


def test_validate_xsd2(ed2):
    ed2.validate_xsd()

def test_validate_xsd8(policystore1):
    with pytest.raises(lxml.etree.XMLSyntaxError):
        ed8 = SAMLEntityDescriptorPVP(ed_path(8), policystore1)


def test_validate_xsd9(ed9):
    with pytest.raises(InvalidSamlXmlSchemaError):
        ed9.validate_xsd()


def test_validateDomainNames1(ed1, namespaces7):
    with pytest.raises(InvalidFQDNinEntityID):
        ed1.validateDomainNames(namespaces7)

def test_validateDomainNames7(ed7, namespaces7):
    ed7.validateDomainNames(namespaces7)

def test_validateDomainNames15(ed15, namespaces7):
    with pytest.raises(InvalidFQDNInEndpoint):
        ed15.validateDomainNames(namespaces7)


def test_validateSignature1(ed1):
    with pytest.raises(ValidationError):
        ed1.validateSignature()

def test_validateSignature10(ed10):
    ed10.validateSignature()

def test_validateSignature11(ed11):
    ed11.validateSignature()


def test_verify_filename2(ed2):
    with pytest.raises(InputValueError):
        ed2.verify_filename()

def test_verify_filename0(ed0):
    ed0.verify_filename()


#def test_write():
#   test included by test_remove_enveloped_signature

