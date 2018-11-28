import json
import pytest
from PVZDpy.samlentitydescriptor import SAMLEntityDescriptor
from PVZDpy.userexceptions import InputValueError
from PVZDpy.tests.common_fixtures import cert1, ed_path

@pytest.fixture
def ed3():
    return SAMLEntityDescriptor(ed_path=ed_path(3))

@pytest.fixture
def xml_str1():
    # xml encoding _must_ be utf-8
    with open('ed_path(3)') as fd:
        return fd.read()

@pytest.fixture
def entityid():
    return 'https://idp.example.com/idp.xml'

@pytest.fixture
def entityid3():
    return 'https://idp3.example.com/idp.xml'

@pytest.fixture
def result19():
    with open(ed_path(19)) as fd:
        return fd.read()

@pytest.fixture
def result20():
    with open(ed_path(20)) as fd:
        return fd.read()


def test_cert2ed(cert1, result19):
    ed_str = SAMLEntityDescriptor.cert2ed(
            cert_str=cert1,
            entityid=entityid(),
            samlrole='IDP')
    assert ed_str == result19

def test_cert2ed(cert1, result20):
    ed = SAMLEntityDescriptor(createfromcertstr=cert1,
                              entityid=entityid(),
                              samlrole='IDP')
    ed_str = ed.get_xml_str()
    assert ed_str == result20


# def test_create_delete():
#     self.fail()

def test_get_entityid(ed3, entityid3):
    assert ed3.get_entityid() == entityid3

#def test_get_xml_str():
#    x = ed3().get_xml_str().rstrip()
#    y = xml_str1().rstrip()
#    assert x == y

def test_get_signing_certs(ed3):
    x = ed3.get_signing_certs()
    assert isinstance(x, list)

def test_get_namespace_prefix(ed3):
    assert ed3.get_namespace_prefix() == 'md'

def test_get_filename_from_entityid():
    assert SAMLEntityDescriptor.get_filename_from_entityid(ed3().get_entityid()) == 'idp3ExampleCom_idpXml.xml'

def test_validate_xsd(ed3):
    ed3.validate_xsd()

# def test_validate_schematron():
#     self.fail()

# def test_write():
#     tested with wrapper (samled_pvp.py)


