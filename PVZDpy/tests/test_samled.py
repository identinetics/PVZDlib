import json
import pytest
from PVZDpy.samlentitydescriptor import SAMLEntityDescriptor
from PVZDpy.userexceptions import InputValueError
from PVZDpy.tests.common_fixtures import cert1, ed_path

@pytest.fixture
def ed1():
    return SAMLEntityDescriptor(ed_path=ed_path(3))

@pytest.fixture
def xml_str1():
    # xml encoding _must_ be utf-8
    with open('ed_path(3)') as fd:
        return fd.read()

@pytest.fixture
def entityid1():
    return 'https://idp.example.com/idp.xml'

@pytest.fixture
def result19():
    with open(ed_path(19)) as fd:
        return fd.read()

@pytest.fixture
def result20():
    with open(ed_path(20)) as fd:
        return fd.read()


def test_cert2ed():
    ed_str = SAMLEntityDescriptor.cert2ed(
            cert_str=cert1(),
            entityid=entityid1(),
            samlrole='IDP')
    assert ed_str == result19()
    ed = SAMLEntityDescriptor(createfromcertstr=cert1(),
                              entityid=entityid1(),
                              samlrole='IDP')
    ed_str = ed.get_xml_str()
    assert ed_str == result20()


# def test_create_delete():
#     self.fail()

def test_get_entityid():
    assert ed1().get_entityid() == entityid1()

#def test_get_xml_str():
#    x = ed1().get_xml_str().rstrip()
#    y = xml_str1().rstrip()
#    assert x == y

def test_get_signing_certs():
    x = ed1().get_signing_certs()
    assert isinstance(x, list)

def test_get_namespace_prefix():
    assert ed1().get_namespace_prefix() == 'md'

def test_get_filename_from_entityid():
    assert SAMLEntityDescriptor.get_filename_from_entityid(ed1().get_entityid()) == 'idpExampleCom_idpXml.xml'

def test_validate_xsd():
    ed1().validate_xsd()

# def test_validate_schematron():
#     self.fail()

# def test_write():
#     tested with wrapper (samled_pvp.py)


