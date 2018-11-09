import json
import lxml.etree
import pytest
import tempfile
from PVZDpy.constants import *
from PVZDpy.userexceptions import *
from PVZDpy.samled_pvp import SAMLEntityDescriptorPVP
from PVZDpy.tests.common_fixtures import *

#path_prefix_testin = 'PVZDpy/tests/testdata/saml/'

@pytest.fixture
def domains7():
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
        ed(5).checkCerts()
    with pytest.raises(CertExpiredError):
        ed(12).checkCerts()
    ed(6).checkCerts()
    with pytest.raises(MultipleEntitiesNotAllowed):
        ed(13).checkCerts()
    with pytest.raises(EdHostnameNotMatchingCertSubject):
        ed(14).checkCerts()


def test_create_delete():
    delete_requ = SAMLEntityDescriptorPVP.create_delete('https://idp.example.com/idp.xml')
    with open(ed_path(4)) as fd:
        assert delete_requ == fd.read()


def test_getAllowedDomainsForOrgs():
    allowed_domains = ed(7).getAllowedDomainsForOrgs(orgids7())
    assert allowed_domains == domains7()


def test_get_orgids_for_signer():
    orgids = ed(2).get_orgids_for_signer(signerCert7())
    assert orgids == ['AT:VKZ:XFN-318886a']


def test_isDeletionRequest():
    assert ed(2).isDeletionRequest() == False
    assert ed(4).isDeletionRequest() == True


def test_remove_enveloped_signature():
    ed10 = ed(10)
    ed10.remove_enveloped_signature()
    fn10_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test10_edit', suffix='xml').name
    ed10.write(fn10_edit)
    with open(ed_path(17)) as fd17:
        with open(fn10_edit) as fn10_edit:
            assert fn10_edit.read() == fd17.read()


def test_set_registrationinfo():
    ed14=ed(1)
    # make expected equal to actual with fake registrationInstant = "1900-01-01T00:00:00Z"
    SAMLEntityDescriptorPVP.set_registrationinfo(ed14.ed.tree, SAML_MDPRI_REGISTRATIONAUTHORITY, fixed_date_for_unittest=True)
    fn14_edit = tempfile.NamedTemporaryFile(mode='w', prefix='test14_edit', suffix='xml').name
    ed14.write(fn14_edit)
    with open(ed_path(16)) as fd1:
        with open(fn14_edit) as fd2:
            assert  fd2.read() == fd1.read()
    os.unlink(fn14_edit)


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
        ed(1).validateDomainNames(domains7())
    ed(7).validateDomainNames(domains7())
    with pytest.raises(InvalidFQDNInEndpoint):
        ed(15).validateDomainNames(domains7())


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

