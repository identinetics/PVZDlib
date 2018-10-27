import json
import lxml.etree
import pytest
from PVZDpy.constants import *
from PVZDpy.userexceptions import *
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP

#path_prefix = 'PVZDpy/tests/testdata/'
path_prefix = 'testdata/'

@pytest.fixture
def domains7():
    return ['*.identinetics.com']

@pytest.fixture
def orgids7():
    return ['AT:VKZ:XFN-318886a']

@pytest.fixture
def poldir1():
    with open(path_prefix+'poldir1.json') as fd:
        d = json.load(fd)
    return d

@pytest.fixture
def signerCert7():
    with open(path_prefix+'signercert7_rh.pem') as fd:
        return fd.read()

@pytest.fixture
def ed_path(file_index: int):
    path = (
        'idpExampleCom_idpXml.xml',
        '01_idp_valid_cert.xml',
        '02_idp_valid_xml_invalid_cert.xml',
        '03_idp_valid_unsigned_c14n.xml',
        '04_idp_delete.xml',
        '05_idp_cert_untrusted_root.xml',
        '06_idp_valid_expired_cert.xml',
        '07_idp_identinetics.xml',
        '08_idp_invalidXml.xml',
        '09_idp_invalidXsd.xml',
        '10_idp_signed.xml',
        '11_idp_unauthz_signator.xml',
        '12_idp_entitiesdescriptor.xml',
        '13_idp_entitiesdescriptor_2idps.xml',
        '14_01_plus_reginfo.xml',
        '15_10_signature_removed.xml',
    )
    return path_prefix + path[file_index]

@pytest.fixture
def ed(file_index: int):
    return SAMLEntityDescriptorPVP(ed_path(file_index), poldir1())


def test_checkCerts():
    ed(1).checkCerts()
    with pytest.raises(CertInvalidError):
        ed(5).checkCerts()
    with pytest.raises(CertExpiredError):
        ed(6).checkCerts()
    ed(12).checkCerts()
    with pytest.raises(MultipleEntitiesNotAllowed):
        ed(13).checkCerts()


def test_create_delete():
    delete_requ = SAMLEntityDescriptorPVP.create_delete('https://idp.example.com/idp.xml')
    with open(ed_path(4)) as fd:
        assert delete_requ == fd.read()


def test_getAllowedDomainsForOrgs():
    allowed_domains = ed(7).getAllowedDomainsForOrgs(orgids7())
    assert allowed_domains == domains7()


def test_getOrgIDs():
    orgids = ed(2).getOrgIDs(signerCert7())
    assert orgids == ['AT:VKZ:XFN-318886a']


def test_isDeletionRequest():
    assert ed(2).isDeletionRequest() == False
    assert ed(4).isDeletionRequest() == True


#def test_modify_and_write_ed():
#    ed = ed(1)
#    ed.tree

def test_remove_enveloped_signature():
    ed10 = ed(10)
    ed10.remove_enveloped_signature()
    with open(ed_path(15)) as fd:
        assert ed10.get_xml_str() == fd.read()

def test_set_registrationinfo():
    ed1=ed(1)
    # make expected equal to actual with fake registrationInstant = "1900-01-01T00:00:00Z"
    ed1.set_registrationinfo(SAML_MDPRI_REGISTRATIONAUTHORITY, fixed_date_for_unittest=True)
    with open(ed_path(14)) as fd:
        assert ed1.get_xml_str() == fd.read()

def test_validate_schematron():
    ed(2).validate_schematron()


def test_validate_xsd():
    ed(2).validate_xsd()
    with pytest.raises(lxml.etree.XMLSyntaxError):
        ed(8).validate_xsd()
    with pytest.raises(InvalidSamlXmlSchemaError):
        ed(9).validate_xsd()


def test_validateDomainNames():
    with pytest.raises(InvalidFQDNError):
        ed(1).validateDomainNames(domains7())
    ed(7).validateDomainNames(domains7())

def test_validateSignature():
    with pytest.raises(ValidationError):
        ed(1).validateSignature()
    ed(10).validateSignature()
    ed(11).validateSignature()

def test_verify_filename():
    with pytest.raises(InputValueError):
        ed(2).verify_filename()
    ed(0).verify_filename()
