import json
import pytest
from PVZDpy.samlentitydescriptor import SAMLEntityDescriptor
from PVZDpy.userexceptions import InputValueError

#path_prefix = 'PVZDpy/tests/testdata/saml/'
path_prefix = 'testdata/saml/'

@pytest.fixture
def cert1():
    with open(path_prefix+'cert1_redmineIdentineticsCom-cer.pem') as fd:
        return fd.read()

@pytest.fixture
def ed1():
    return SAMLEntityDescriptor(ed_path=path_prefix+'03_idp_valid_unsigned_c14n.xml')

@pytest.fixture
def xml_str1():
    # xml encoding _must_ be utf-8
    with open(path_prefix+'03_idp_valid_unsigned_c14n.xml') as fd:
        return fd.read()

@pytest.fixture
def entityid1():
    return 'https://idp.example.com/idp.xml'

@pytest.fixture
def result16a():
    with open(path_prefix+'18a_ed_from_cert.xml') as fd:
        return fd.read()

@pytest.fixture
def result16b():
    with open(path_prefix+'18b_ed_from_cert.xml') as fd:
        return fd.read()


def test_cert2ed():
    ed_str = SAMLEntityDescriptor.cert2ed(
            cert_str=cert1(),
            entityid=entityid1(),
            samlrole='IDP')
    assert ed_str == result16a()
    ed = SAMLEntityDescriptor(createfromcertstr=cert1(),
                              entityid=entityid1(),
                              samlrole='IDP')
    ed_str = ed.get_xml_str()
    assert ed_str == result16b()


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
    assert ed1().get_filename_from_entityid() == 'idpExampleCom_idpXml.xml'

def test_validate_xsd():
    ed1().validate_xsd()

# def test_validate_schematron():
#     self.fail()

# def test_write():
#     tested with wrapper (samled_pvp.py)


