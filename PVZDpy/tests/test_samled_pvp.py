import json
import pytest
from PVZDpy.userexceptions import *
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP

#path_prefix = 'PVZDpy/tests/testdata/'
path_prefix = 'testdata/'

@pytest.fixture
def orgids1():
    return []

@pytest.fixture
def poldir1():
    with open(path_prefix+'poldir1.json') as fd:
        d = json.load(fd)
    return d

@pytest.fixture
def signerCert1():
    with open(path_prefix+'signercert1.pem') as fd:
        return fd.read()


#@pytest.fixture
#def ed1():
#    return SAMLEntityDescriptorPVP(path_prefix+'01_idp_valid_cert.xml', poldir1())


@pytest.fixture
def ed2():
    return SAMLEntityDescriptorPVP(path_prefix+'02_idp_valid_xml_invalid_cert.xml', poldir1())


@pytest.fixture
def ed4():
    return SAMLEntityDescriptorPVP(path_prefix+'04_idp_delete.xml', poldir1())


@pytest.fixture
def ed5():
    return SAMLEntityDescriptorPVP(path_prefix + '05_idp_cert_untrusted_root.xml', poldir1())


@pytest.fixture
def ed6():
    return SAMLEntityDescriptorPVP(path_prefix + '06_idp_valid_expired_cert.xml', poldir1())


def test_checkCerts():
    # ed1().checkCerts()  ## need to create valid cert that does not expire too soon
    with pytest.raises(CertInvalidError):
        ed5().checkCerts()
    with pytest.raises(CertExpiredError):
        ed6().checkCerts()


#def test_create_delete():


def test_getAllowedDomainsForOrgs():
    allowed_domains = ed2().getAllowedDomainsForOrgs(orgids1())
    assert allowed_domains == []


def test_getOrgIDs():
    orgids = ed2().getOrgIDs(signerCert1())
    assert orgids == ['AT:VKZ:XFN-318886a']

    # with pytest.raises(UnauthorizedSignerError):

def test_isDeletionRequest():
    assert ed2().isDeletionRequest() == False
    assert ed4().isDeletionRequest() == True


#def test_modify_and_write_ed():


def test_validate_schematron():
    ed2().validate_schematron()


def test_validate_xsd():
    ed2().validate_xsd()


#def test_validateDomainNames():


#def test_validateSignature():


def test_verify_filename():
    with pytest.raises(InputValueError):
        ed2().verify_filename()
